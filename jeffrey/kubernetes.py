from __future__ import annotations

import json
import os
import subprocess
from collections.abc import Callable
from pathlib import Path

from rich.console import Console

from jeffrey.models import CommandResult, EnvironmentCheck, KubernetesEvidence

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
        evidence = KubernetesEvidence(namespace=namespace, deployment=deployment)

        evidence.environment = self.verify_environment()
        evidence.executed_commands.extend(evidence.environment.commands)
        for result in evidence.environment.commands:
            self._record_error(evidence, result)

        self.debug_fn("Collecting deployment evidence...")
        evidence.deployment_json = self._run(
            ["kubectl", "get", "deployment", deployment, "-n", namespace, "-o", "json"]
        )
        evidence.executed_commands.append(evidence.deployment_json)
        self._record_error(evidence, evidence.deployment_json)
        evidence.selector = selector_from_deployment_json(evidence.deployment_json)
        evidence.selector_text = selector_to_text(evidence.selector)
        if evidence.selector_text:
            self.debug_fn(f"Deployment selector:\n{evidence.selector_text}")

        evidence.deployment_description = self._run(
            ["kubectl", "describe", "deployment", deployment, "-n", namespace]
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
                ]
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
                ["kubectl", "get", "pods", "-n", namespace, "-o", "json"]
            )
            evidence.executed_commands.append(evidence.pods_json)
            self._record_error(evidence, evidence.pods_json)
            selected_pods = identify_related_pods_from_json(evidence.pods_json, deployment)

        evidence.pods_output = self._run(["kubectl", "get", "pods", "-n", namespace])
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
            ["kubectl", "get", "events", "-n", namespace, "--sort-by=.lastTimestamp"]
        )
        evidence.events_output = evidence.namespace_events_output
        evidence.executed_commands.append(evidence.namespace_events_output)
        self._record_error(evidence, evidence.namespace_events_output)
        evidence.unrelated_namespace_events_ignored = count_unrelated_namespace_events(evidence)

        self.debug_fn("Collecting container logs...")
        for pod_name in evidence.selected_pods:
            self.debug_fn(f"Selected pod:\n{pod_name}")
            describe_result = self._run(["kubectl", "describe", "pod", pod_name, "-n", namespace])
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
                ]
            )
            evidence.pod_events[pod_name] = pod_events_result
            evidence.executed_commands.append(pod_events_result)
            self._record_error(evidence, pod_events_result)

            logs_result = self._run(
                ["kubectl", "logs", pod_name, "-n", namespace, "--tail=200"]
            )
            evidence.pod_logs[pod_name] = logs_result
            evidence.executed_commands.append(logs_result)
            self._record_error(evidence, logs_result)

            previous_logs_result = self._run(
                ["kubectl", "logs", pod_name, "-n", namespace, "--previous", "--tail=200"]
            )
            evidence.pod_previous_logs[pod_name] = previous_logs_result
            evidence.executed_commands.append(previous_logs_result)
            self._record_error(evidence, previous_logs_result)

        evidence.correlated_events_found = sum(
            len(correlated_lines_from_command(result))
            for result in evidence.pod_events.values()
        )
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

        namespace = self._run(
            ["kubectl", "config", "view", "--minify", "--output", "jsonpath={..namespace}"]
        )
        check.commands.append(namespace)
        if namespace.succeeded and namespace.stdout.strip():
            check.current_namespace = namespace.stdout.strip()
            self.debug_fn(f"Current namespace:\n{check.current_namespace}")

        return check

    def _run(self, command: list[str]) -> CommandResult:
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
    def _record_error(evidence: KubernetesEvidence, result: CommandResult) -> None:
        if not result.succeeded:
            evidence.command_errors.append(result)

    def _debug(self, message: str) -> None:
        if self.debug:
            self.console.print(f"[dim][DEBUG] {message}[/dim]")


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


def _pod_status_rank(status: str) -> int:
    ranks = {
        "Running": 0,
        "CrashLoopBackOff": 1,
        "Error": 2,
    }
    return ranks.get(status, 3)
