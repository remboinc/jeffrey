from __future__ import annotations

import json
import os
import subprocess
from collections.abc import Callable
from pathlib import Path

from rich.console import Console

from jeffrey.models import (
    CommandResult,
    EnvironmentCheck,
    KubernetesEvidence,
    KubernetesJobEvidence,
)

DEFAULT_KUBE_TIMEOUT = 15
MAX_PODS_TO_COLLECT = 3
DebugFn = Callable[[str], None]


def run_command(command: list[str], timeout: int = DEFAULT_KUBE_TIMEOUT) -> CommandResult:
    try:
        completed = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except FileNotFoundError as error:
        return CommandResult(
            command=command,
            exit_code=None,
            stderr=f"Command not found: {error.filename}",
        )
    except subprocess.TimeoutExpired as error:
        return CommandResult(
            command=command,
            exit_code=None,
            stdout=error.stdout or "",
            stderr=error.stderr or f"Command timed out after {timeout}s",
            timed_out=True,
        )

    return CommandResult(
        command=command,
        exit_code=completed.returncode,
        stdout=completed.stdout,
        stderr=completed.stderr,
    )


class KubernetesCollector:
    def __init__(
        self,
        *,
        timeout: int = DEFAULT_KUBE_TIMEOUT,
        show_commands: bool = False,
        debug: bool = False,
        console: Console | None = None,
        debug_fn: DebugFn | None = None,
    ) -> None:
        self.timeout = timeout
        self.show_commands = show_commands
        self.debug = debug
        self.console = console or Console()
        self.debug_fn = debug_fn or self._debug

    def collect(self, namespace: str, deployment: str) -> KubernetesEvidence:
        environment = self.verify_environment()
        failed_attempt_commands: list[CommandResult] = []
        failed_attempt_errors: list[CommandResult] = []
        failed_attempt_contexts: list[str] = []

        for command_context, display_context in self._contexts_to_try(environment):
            self.debug_fn(f"Trying Kubernetes context:\n{display_context}")
            evidence = self._collect_deployment_in_context(
                namespace,
                deployment,
                command_context=command_context,
                display_context=display_context,
                environment=environment,
                previous_commands=failed_attempt_commands,
                previous_errors=failed_attempt_errors,
                previous_contexts=failed_attempt_contexts,
            )
            if not _resource_not_found(evidence.deployment_json):
                return evidence
            self.debug_fn(
                f"Deployment {deployment} was not found in context {display_context}"
            )
            failed_attempt_commands.extend(
                command
                for command in evidence.executed_commands
                if command not in environment.commands
            )
            failed_attempt_errors.extend(
                command
                for command in evidence.command_errors
                if command not in environment.commands
            )
            failed_attempt_contexts.append(display_context)

        return evidence

    def _collect_deployment_in_context(
        self,
        namespace: str,
        deployment: str,
        *,
        command_context: str | None,
        display_context: str,
        environment: EnvironmentCheck,
        previous_commands: list[CommandResult],
        previous_errors: list[CommandResult],
        previous_contexts: list[str],
    ) -> KubernetesEvidence:
        evidence = KubernetesEvidence(
            namespace=namespace,
            deployment=deployment,
            environment=environment,
            context=display_context,
            attempted_contexts=[*previous_contexts, display_context],
        )
        evidence.executed_commands.extend(environment.commands)
        evidence.executed_commands.extend(previous_commands)
        evidence.command_errors.extend(previous_errors)
        for result in environment.commands:
            self._record_error(evidence, result)

        self.debug_fn("Collecting deployment evidence...")
        evidence.deployment_json = self._run(
            ["kubectl", "get", "deployment", deployment, "-n", namespace, "-o", "json"],
            context=command_context,
        )
        evidence.executed_commands.append(evidence.deployment_json)
        self._record_error(evidence, evidence.deployment_json)
        if _resource_not_found(evidence.deployment_json):
            return evidence

        evidence.selector = selector_from_deployment_json(evidence.deployment_json)
        evidence.selector_text = selector_to_text(evidence.selector)
        if evidence.selector_text:
            self.debug_fn(f"Deployment selector:\n{evidence.selector_text}")

        evidence.deployment_description = self._run(
            ["kubectl", "describe", "deployment", deployment, "-n", namespace],
            context=command_context,
        )
        evidence.executed_commands.append(evidence.deployment_description)
        self._record_error(evidence, evidence.deployment_description)
        evidence.replica_sets = replica_sets_from_deployment_describe(
            evidence.deployment_description
        )

        self.debug_fn("Collecting pod evidence...")
        selected_pods: list[str] = []
        if evidence.selector_text:
            evidence.labeled_pods_output = self._run(
                [
                    "kubectl",
                    "get",
                    "pods",
                    "-n",
                    namespace,
                    "-l",
                    evidence.selector_text,
                    "-o",
                    "json",
                ],
                context=command_context,
            )
            evidence.pods_json = evidence.labeled_pods_output
            evidence.executed_commands.append(evidence.labeled_pods_output)
            self._record_error(evidence, evidence.labeled_pods_output)
            selected_pods = pod_names_from_pods_json(evidence.labeled_pods_output)
            evidence.selector_lookup_failed = not selected_pods
        else:
            evidence.selector_lookup_failed = True

        if not selected_pods:
            evidence.fallback_pod_matching_used = True
            evidence.pods_json = self._run(
                ["kubectl", "get", "pods", "-n", namespace, "-o", "json"],
                context=command_context,
            )
            evidence.executed_commands.append(evidence.pods_json)
            self._record_error(evidence, evidence.pods_json)
            selected_pods = identify_related_pods_from_json(evidence.pods_json, deployment)

        evidence.pods_output = self._run(
            ["kubectl", "get", "pods", "-n", namespace],
            context=command_context,
        )
        evidence.executed_commands.append(evidence.pods_output)
        self._record_error(evidence, evidence.pods_output)

        if evidence.fallback_pod_matching_used and not selected_pods:
            selected_pods = identify_related_pods(evidence.pods_output, deployment)

        if evidence.labeled_pods_output is None and evidence.pods_json is not None:
            evidence.labeled_pods_output = evidence.pods_json

        evidence.selected_pods = selected_pods[:MAX_PODS_TO_COLLECT]
        if evidence.selected_pods:
            self.debug_fn("Found pods:\n" + "\n".join(evidence.selected_pods))

        self.debug_fn("Collecting namespace event context...")
        evidence.namespace_events_output = self._run(
            ["kubectl", "get", "events", "-n", namespace, "--sort-by=.lastTimestamp"],
            context=command_context,
        )
        evidence.events_output = evidence.namespace_events_output
        evidence.executed_commands.append(evidence.namespace_events_output)
        self._record_error(evidence, evidence.namespace_events_output)
        evidence.unrelated_namespace_events_ignored = count_unrelated_namespace_events(evidence)

        self.debug_fn("Collecting container logs...")
        for pod_name in evidence.selected_pods:
            self.debug_fn(f"Selected pod:\n{pod_name}")
            describe_result = self._run(
                ["kubectl", "describe", "pod", pod_name, "-n", namespace],
                context=command_context,
            )
            evidence.pod_descriptions[pod_name] = describe_result
            evidence.executed_commands.append(describe_result)
            self._record_error(evidence, describe_result)

            pod_events_result = self._run(
                [
                    "kubectl",
                    "get",
                    "events",
                    "-n",
                    namespace,
                    f"--field-selector=involvedObject.name={pod_name}",
                    "--sort-by=.lastTimestamp",
                ],
                context=command_context,
            )
            evidence.pod_events[pod_name] = pod_events_result
            evidence.executed_commands.append(pod_events_result)
            self._record_error(evidence, pod_events_result)

            logs_result = self._run(
                ["kubectl", "logs", pod_name, "-n", namespace, "--tail=200"],
                context=command_context,
            )
            evidence.pod_logs[pod_name] = logs_result
            evidence.executed_commands.append(logs_result)
            self._record_error(evidence, logs_result)

            previous_logs_result = self._run(
                ["kubectl", "logs", pod_name, "-n", namespace, "--previous", "--tail=200"],
                context=command_context,
            )
            evidence.pod_previous_logs[pod_name] = previous_logs_result
            evidence.executed_commands.append(previous_logs_result)
            self._record_error(evidence, previous_logs_result)

        evidence.correlated_events_found = sum(
            len(correlated_lines_from_command(result))
            for result in evidence.pod_events.values()
        )
        return evidence

    def collect_job(self, namespace: str, job: str) -> KubernetesJobEvidence:
        environment = self.verify_environment()
        failed_attempt_commands: list[CommandResult] = []
        failed_attempt_errors: list[CommandResult] = []
        failed_attempt_contexts: list[str] = []

        for command_context, display_context in self._contexts_to_try(environment):
            self.debug_fn(f"Trying Kubernetes context:\n{display_context}")
            evidence = self._collect_job_in_context(
                namespace,
                job,
                command_context=command_context,
                display_context=display_context,
                environment=environment,
                previous_commands=failed_attempt_commands,
                previous_errors=failed_attempt_errors,
                previous_contexts=failed_attempt_contexts,
            )
            if not _resource_not_found(evidence.job_json):
                return evidence
            self.debug_fn(f"Job {job} was not found in context {display_context}")
            failed_attempt_commands.extend(
                command
                for command in evidence.executed_commands
                if command not in environment.commands
            )
            failed_attempt_errors.extend(
                command
                for command in evidence.command_errors
                if command not in environment.commands
            )
            failed_attempt_contexts.append(display_context)

        return evidence

    def _collect_job_in_context(
        self,
        namespace: str,
        job: str,
        *,
        command_context: str | None,
        display_context: str,
        environment: EnvironmentCheck,
        previous_commands: list[CommandResult],
        previous_errors: list[CommandResult],
        previous_contexts: list[str],
    ) -> KubernetesJobEvidence:
        evidence = KubernetesJobEvidence(
            namespace=namespace,
            job=job,
            environment=environment,
            context=display_context,
            attempted_contexts=[*previous_contexts, display_context],
        )
        evidence.executed_commands.extend(environment.commands)
        evidence.executed_commands.extend(previous_commands)
        evidence.command_errors.extend(previous_errors)
        for result in environment.commands:
            self._record_error(evidence, result)

        self.debug_fn("Collecting Job evidence...")
        evidence.job_json = self._run(
            ["kubectl", "get", "job", job, "-n", namespace, "-o", "json"],
            context=command_context,
        )
        evidence.executed_commands.append(evidence.job_json)
        self._record_error(evidence, evidence.job_json)
        if _resource_not_found(evidence.job_json):
            return evidence

        evidence.job_description = self._run(
            ["kubectl", "describe", "job", job, "-n", namespace],
            context=command_context,
        )
        evidence.executed_commands.append(evidence.job_description)
        self._record_error(evidence, evidence.job_description)

        evidence.selector = selector_from_job_json(evidence.job_json)
        evidence.selector_text = selector_to_text(evidence.selector)

        selected_pods: list[str] = []
        pod_statuses: dict[str, str] = {}
        if evidence.selector_text:
            evidence.job_pods_json = self._run(
                [
                    "kubectl",
                    "get",
                    "pods",
                    "-n",
                    namespace,
                    "-l",
                    evidence.selector_text,
                    "-o",
                    "json",
                ],
                context=command_context,
            )
            evidence.executed_commands.append(evidence.job_pods_json)
            self._record_error(evidence, evidence.job_pods_json)
            selected_pods = job_pod_names_from_json(evidence.job_pods_json)
            pod_statuses = pod_statuses_from_json(evidence.job_pods_json)
            evidence.selector_lookup_failed = not selected_pods
        else:
            evidence.selector_lookup_failed = True

        for label in (f"job-name={job}", f"batch.kubernetes.io/job-name={job}"):
            if selected_pods:
                break
            evidence.fallback_label_used = label
            evidence.job_pods_json = self._run(
                ["kubectl", "get", "pods", "-n", namespace, "-l", label, "-o", "json"],
                context=command_context,
            )
            evidence.executed_commands.append(evidence.job_pods_json)
            self._record_error(evidence, evidence.job_pods_json)
            selected_pods = job_pod_names_from_json(evidence.job_pods_json)
            pod_statuses = pod_statuses_from_json(evidence.job_pods_json)

        label_for_text = evidence.selector_text or evidence.fallback_label_used
        if label_for_text:
            evidence.job_pods_output = self._run(
                ["kubectl", "get", "pods", "-n", namespace, "-l", label_for_text],
                context=command_context,
            )
        else:
            evidence.job_pods_output = self._run(
                ["kubectl", "get", "pods", "-n", namespace],
                context=command_context,
            )
        evidence.executed_commands.append(evidence.job_pods_output)
        self._record_error(evidence, evidence.job_pods_output)

        evidence.selected_pods = selected_pods[:MAX_PODS_TO_COLLECT]
        evidence.pod_statuses = {
            pod_name: pod_statuses.get(pod_name, "Unknown")
            for pod_name in evidence.selected_pods
        }

        for pod_name in evidence.selected_pods:
            describe_result = self._run(
                ["kubectl", "describe", "pod", pod_name, "-n", namespace],
                context=command_context,
            )
            evidence.pod_descriptions[pod_name] = describe_result
            evidence.executed_commands.append(describe_result)
            self._record_error(evidence, describe_result)

            logs_result = self._run(
                ["kubectl", "logs", pod_name, "-n", namespace, "--tail=200"],
                context=command_context,
            )
            evidence.pod_logs[pod_name] = logs_result
            evidence.executed_commands.append(logs_result)
            self._record_error(evidence, logs_result)

            previous_logs_result = self._run(
                ["kubectl", "logs", pod_name, "-n", namespace, "--previous", "--tail=200"],
                context=command_context,
            )
            evidence.pod_previous_logs[pod_name] = previous_logs_result
            evidence.executed_commands.append(previous_logs_result)
            self._record_error(evidence, previous_logs_result)

            pod_events_result = self._run(
                [
                    "kubectl",
                    "get",
                    "events",
                    "-n",
                    namespace,
                    f"--field-selector=involvedObject.name={pod_name}",
                    "--sort-by=.lastTimestamp",
                ],
                context=command_context,
            )
            evidence.pod_events[pod_name] = pod_events_result
            evidence.executed_commands.append(pod_events_result)
            self._record_error(evidence, pod_events_result)

        return evidence

    def verify_environment(self) -> EnvironmentCheck:
        check = EnvironmentCheck()

        version = self._run(["kubectl", "version", "--client"])
        check.commands.append(version)
        check.kubectl_found = version.exit_code is not None
        if check.kubectl_found:
            check.messages.append("kubectl found")
            self.debug_fn("kubectl found")
        else:
            check.messages.append("kubectl is not installed or not on PATH")
            self.debug_fn("kubectl is not installed or not on PATH")

        kubeconfig_path = os.environ.get("KUBECONFIG") or str(Path.home() / ".kube" / "config")
        check.kubeconfig_loaded = Path(kubeconfig_path).exists()
        if check.kubeconfig_loaded:
            check.messages.append("kubeconfig loaded")
            self.debug_fn("kubeconfig loaded")
        else:
            check.messages.append(f"kubeconfig not found at {kubeconfig_path}")
            self.debug_fn(f"kubeconfig not found at {kubeconfig_path}")

        context = self._run(["kubectl", "config", "current-context"])
        check.commands.append(context)
        if context.succeeded and context.stdout.strip():
            check.current_context = context.stdout.strip()
            self.debug_fn(f"current context:\n{check.current_context}")

        contexts = self._run(["kubectl", "config", "get-contexts", "-o", "name"])
        check.commands.append(contexts)
        if contexts.succeeded:
            check.contexts = [
                line.strip()
                for line in contexts.stdout.splitlines()
                if line.strip()
            ]
            if check.contexts:
                self.debug_fn("available contexts:\n" + "\n".join(check.contexts))

        namespace = self._run(
            ["kubectl", "config", "view", "--minify", "--output", "jsonpath={..namespace}"]
        )
        check.commands.append(namespace)
        if namespace.succeeded and namespace.stdout.strip():
            check.current_namespace = namespace.stdout.strip()
            self.debug_fn(f"Current namespace:\n{check.current_namespace}")

        return check

    def _run(self, command: list[str], *, context: str | None = None) -> CommandResult:
        command = _command_with_context(command, context)
        if self.show_commands:
            self.console.print(f"$ {' '.join(command)}")
        self.debug_fn("Running:\n" + " ".join(command))
        result = run_command(command, timeout=self.timeout)
        self.debug_fn(f"kubectl exit code: {result.exit_code}")
        if result.stderr.strip():
            self.debug_fn(f"kubectl stderr:\n{result.stderr.strip()}")
        if result.timed_out:
            self.debug_fn("kubectl command timed out")
        return result

    @staticmethod
    def _record_error(
        evidence: KubernetesEvidence | KubernetesJobEvidence,
        result: CommandResult,
    ) -> None:
        if not result.succeeded:
            evidence.command_errors.append(result)

    def _debug(self, message: str) -> None:
        if self.debug:
            self.console.print(f"[dim][DEBUG] {message}[/dim]")

    def _contexts_to_try(self, environment: EnvironmentCheck) -> list[tuple[str | None, str]]:
        current_context = environment.current_context or "current"
        contexts: list[tuple[str | None, str]] = [(None, current_context)]
        for context in environment.contexts:
            if context == environment.current_context:
                continue
            contexts.append((context, context))
        return contexts


def _command_with_context(command: list[str], context: str | None) -> list[str]:
    if context is None or not command or command[0] != "kubectl":
        return command
    return ["kubectl", "--context", context, *command[1:]]


def _resource_not_found(result: CommandResult | None) -> bool:
    if result is None or result.succeeded:
        return False
    text = f"{result.stdout}\n{result.stderr}".lower()
    compact = text.replace(" ", "")
    return "not found" in text or "notfound" in compact


def identify_related_pods(
    pods_output: CommandResult | None,
    deployment: str,
    *,
    limit: int = MAX_PODS_TO_COLLECT,
) -> list[str]:
    if pods_output is None or not pods_output.stdout:
        return []

    candidates: list[tuple[int, int, str]] = []
    for line in pods_output.stdout.splitlines():
        stripped = line.strip()
        if not stripped or stripped.lower().startswith("name "):
            continue

        columns = stripped.split()
        pod_name = columns[0]
        status = columns[2] if len(columns) >= 3 else ""
        if status == "Completed":
            continue

        if pod_name.startswith(f"{deployment}-") or deployment in pod_name:
            candidates.append((_pod_status_rank(status), len(candidates), pod_name))

    return [pod_name for _, _, pod_name in sorted(candidates)[:limit]]


def selector_from_deployment_json(result: CommandResult | None) -> dict[str, str]:
    if result is None or not result.stdout:
        return {}
    try:
        payload = json.loads(result.stdout)
    except json.JSONDecodeError:
        return {}

    match_labels = (
        payload.get("spec", {})
        .get("selector", {})
        .get("matchLabels", {})
    )
    if not isinstance(match_labels, dict):
        return {}
    return {str(key): str(value) for key, value in match_labels.items()}


def selector_from_job_json(result: CommandResult | None) -> dict[str, str]:
    if result is None or not result.stdout:
        return {}
    try:
        payload = json.loads(result.stdout)
    except json.JSONDecodeError:
        return {}

    match_labels = (
        payload.get("spec", {})
        .get("selector", {})
        .get("matchLabels", {})
    )
    if not isinstance(match_labels, dict):
        return {}
    return {str(key): str(value) for key, value in match_labels.items()}


def selector_to_text(selector: dict[str, str]) -> str | None:
    if not selector:
        return None
    return ",".join(f"{key}={value}" for key, value in sorted(selector.items()))


def pod_names_from_pods_json(
    result: CommandResult | None,
    *,
    limit: int = MAX_PODS_TO_COLLECT,
) -> list[str]:
    if result is None or not result.stdout:
        return []
    try:
        payload = json.loads(result.stdout)
    except json.JSONDecodeError:
        return []

    candidates = []
    for index, item in enumerate(payload.get("items", [])):
        pod_name = item.get("metadata", {}).get("name")
        status = item.get("status", {}).get("phase", "")
        waiting_reason = _waiting_reason_from_pod_item(item)
        rank_status = waiting_reason or status
        if not pod_name or rank_status == "Completed" or status == "Succeeded":
            continue
        candidates.append((_pod_status_rank(rank_status), index, str(pod_name)))

    return [pod_name for _, _, pod_name in sorted(candidates)[:limit]]


def job_pod_names_from_json(
    result: CommandResult | None,
    *,
    limit: int = MAX_PODS_TO_COLLECT,
) -> list[str]:
    if result is None or not result.stdout:
        return []
    try:
        payload = json.loads(result.stdout)
    except json.JSONDecodeError:
        return []

    candidates = []
    for index, item in enumerate(payload.get("items", [])):
        pod_name = item.get("metadata", {}).get("name")
        if not pod_name:
            continue
        status = _pod_status_from_item(item)
        candidates.append((_pod_status_rank(status), index, str(pod_name)))
    return [pod_name for _, _, pod_name in sorted(candidates)[:limit]]


def pod_statuses_from_json(result: CommandResult | None) -> dict[str, str]:
    if result is None or not result.stdout:
        return {}
    try:
        payload = json.loads(result.stdout)
    except json.JSONDecodeError:
        return {}

    statuses = {}
    for item in payload.get("items", []):
        pod_name = item.get("metadata", {}).get("name")
        if pod_name:
            statuses[str(pod_name)] = _pod_status_from_item(item)
    return statuses


def identify_related_pods_from_json(
    result: CommandResult | None,
    deployment: str,
    *,
    limit: int = MAX_PODS_TO_COLLECT,
) -> list[str]:
    if result is None or not result.stdout:
        return []
    try:
        payload = json.loads(result.stdout)
    except json.JSONDecodeError:
        return []

    candidates = []
    for index, item in enumerate(payload.get("items", [])):
        pod_name = item.get("metadata", {}).get("name")
        if not pod_name:
            continue
        status = item.get("status", {}).get("phase", "")
        waiting_reason = _waiting_reason_from_pod_item(item)
        rank_status = waiting_reason or status
        if rank_status == "Completed" or status == "Succeeded":
            continue
        if pod_name.startswith(f"{deployment}-") or deployment in pod_name:
            candidates.append((_pod_status_rank(rank_status), index, str(pod_name)))

    return [pod_name for _, _, pod_name in sorted(candidates)[:limit]]


def replica_sets_from_deployment_describe(result: CommandResult | None) -> list[str]:
    if result is None:
        return []

    replica_sets = []
    for line in result.stdout.splitlines():
        stripped = line.strip()
        if stripped.startswith("NewReplicaSet:"):
            value = stripped.removeprefix("NewReplicaSet:").strip()
            if value and value != "<none>":
                replica_sets.append(value.split()[0])
        elif stripped.startswith("OldReplicaSets:"):
            value = stripped.removeprefix("OldReplicaSets:").strip()
            if value and value != "<none>":
                replica_sets.extend(part.strip(",") for part in value.split() if part != "<none>")
    return list(dict.fromkeys(replica_sets))


def count_unrelated_namespace_events(evidence: KubernetesEvidence) -> int:
    if evidence.namespace_events_output is None:
        return 0

    unrelated = 0
    for line in evidence.namespace_events_output.stdout.splitlines():
        stripped = line.strip()
        if not stripped or stripped.lower().startswith("last seen"):
            continue
        if not event_line_is_correlated(stripped, evidence):
            unrelated += 1
    return unrelated


def event_line_is_correlated(line: str, evidence: KubernetesEvidence) -> bool:
    if evidence.deployment in line:
        return True
    if any(pod_name in line for pod_name in evidence.selected_pods):
        return True
    return any(replica_set in line for replica_set in evidence.replica_sets)


def correlated_lines_from_command(result: CommandResult | None) -> list[str]:
    if result is None:
        return []
    return [line for line in result.stdout.splitlines() if line.strip()]


def _waiting_reason_from_pod_item(item: dict[str, object]) -> str | None:
    container_statuses = item.get("status", {}).get("containerStatuses", [])
    if not isinstance(container_statuses, list):
        return None
    for status in container_statuses:
        if not isinstance(status, dict):
            continue
        state = status.get("state", {})
        if not isinstance(state, dict):
            continue
        waiting = state.get("waiting", {})
        if isinstance(waiting, dict) and waiting.get("reason"):
            return str(waiting["reason"])
        terminated = state.get("terminated", {})
        if isinstance(terminated, dict) and terminated.get("reason"):
            return str(terminated["reason"])
    return None


def _pod_status_from_item(item: dict[str, object]) -> str:
    status = item.get("status", {})
    if not isinstance(status, dict):
        return "Unknown"
    waiting_reason = _waiting_reason_from_pod_item(item)
    if waiting_reason:
        return waiting_reason
    phase = status.get("phase")
    if phase:
        return str(phase)
    return "Unknown"


def _pod_status_rank(status: str) -> int:
    ranks = {
        "Pending": 0,
        "Running": 0,
        "CrashLoopBackOff": 1,
        "Error": 2,
        "Failed": 2,
        "OOMKilled": 2,
        "ImagePullBackOff": 2,
        "CreateContainerConfigError": 2,
        "Completed": 4,
        "Succeeded": 4,
    }
    return ranks.get(status, 3)
