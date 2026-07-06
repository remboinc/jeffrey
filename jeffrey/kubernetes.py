from __future__ import annotations

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
        evidence.deployment_description = self._run(
            ["kubectl", "describe", "deployment", deployment, "-n", namespace]
        )
        evidence.executed_commands.append(evidence.deployment_description)
        self._record_error(evidence, evidence.deployment_description)

        self.debug_fn("Collecting pod evidence...")
        evidence.labeled_pods_output = self._run(
            ["kubectl", "get", "pods", "-n", namespace, "-l", f"app={deployment}"]
        )
        evidence.executed_commands.append(evidence.labeled_pods_output)
        self._record_error(evidence, evidence.labeled_pods_output)

        selected_pods = identify_related_pods(evidence.labeled_pods_output, deployment)
        if not selected_pods:
            evidence.pods_output = self._run(["kubectl", "get", "pods", "-n", namespace])
            evidence.executed_commands.append(evidence.pods_output)
            self._record_error(evidence, evidence.pods_output)
            selected_pods = identify_related_pods(evidence.pods_output, deployment)
        else:
            evidence.pods_output = evidence.labeled_pods_output

        evidence.selected_pods = selected_pods
        if selected_pods:
            self.debug_fn("Found pods:\n" + "\n".join(selected_pods))

        self.debug_fn("Collecting event evidence...")
        evidence.events_output = self._run(
            ["kubectl", "get", "events", "-n", namespace, "--sort-by=.lastTimestamp"]
        )
        evidence.executed_commands.append(evidence.events_output)
        self._record_error(evidence, evidence.events_output)

        self.debug_fn("Collecting container logs...")
        for pod_name in selected_pods:
            self.debug_fn(f"Selected pod:\n{pod_name}")
            describe_result = self._run(["kubectl", "describe", "pod", pod_name, "-n", namespace])
            evidence.pod_descriptions[pod_name] = describe_result
            evidence.executed_commands.append(describe_result)
            self._record_error(evidence, describe_result)

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


def _pod_status_rank(status: str) -> int:
    ranks = {
        "Running": 0,
        "CrashLoopBackOff": 1,
        "Error": 2,
    }
    return ranks.get(status, 3)
