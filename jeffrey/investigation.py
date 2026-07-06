from __future__ import annotations

import re
import shlex
import time
from collections.abc import Callable
from pathlib import Path

from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn

from jeffrey.kubernetes import DEFAULT_KUBE_TIMEOUT, KubernetesCollector
from jeffrey.models import BuildInvestigation, Finding, KubernetesEvidence
from jeffrey.scanner import scan_build_log

ROLLOUT_CONTEXT_PATTERN = re.compile(
    r"(?:--namespace(?:=|\s+)|-n\s+)'?(?P<namespace>[^'\s]+)'?.*?"
    r"rollout\s+status\s+deployment\s+(?P<deployment>[^\s']+).*?"
    r"(?:--timeout(?:=|\s+)'?(?P<timeout>[^'\s]+)'?)?",
)


def investigate_build_log(
    path: Path,
    *,
    last_lines: int = 80,
    collect_k8s: bool = True,
    kube_timeout: int = DEFAULT_KUBE_TIMEOUT,
    show_commands: bool = False,
    debug: bool = False,
    console: Console | None = None,
    collector_factory: Callable[..., KubernetesCollector] = KubernetesCollector,
) -> BuildInvestigation:
    console = console or Console()
    started_at = time.monotonic()

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
        transient=True,
    ) as progress:
        task_id = progress.add_task("Investigating Jenkins build...", total=None)
        _debug(console, debug, "Reading Jenkins log...")
        investigation = scan_build_log(path, last_lines=last_lines)
        investigation.duration_seconds = time.monotonic() - started_at
        _debug(console, debug, f"Build status: {investigation.build_status or 'UNKNOWN'}")
        if investigation.likely_root_cause and investigation.likely_root_cause.stage:
            _debug(console, debug, f"Stage: {investigation.likely_root_cause.stage}")
        _progress(console, "Jenkins log parsed")

        if investigation.is_success:
            investigation.duration_seconds = time.monotonic() - started_at
            return investigation

        rollout_finding = _rollout_timeout_finding(investigation)
        if rollout_finding is None or not collect_k8s:
            investigation.duration_seconds = time.monotonic() - started_at
            return investigation

        context = rollout_context_from_finding(rollout_finding)
        if context is None:
            investigation.duration_seconds = time.monotonic() - started_at
            return investigation

        rollout_finding.metadata.update(context)
        _debug(console, debug, f"Extracted namespace:\n{context['namespace']}")
        _debug(console, debug, f"Extracted deployment:\n{context['deployment']}")
        _progress(console, f"Deployment detected: {context['deployment']}")
        _progress(console, f"Namespace detected: {context['namespace']}")
        if "timeout" in context:
            _progress(console, "Rollout timeout detected")

        progress.update(task_id, description="Collecting deployment evidence...")
        _progress(console, "Collecting Kubernetes evidence...")

        collector = collector_factory(
            timeout=kube_timeout,
            show_commands=show_commands,
            debug=debug,
            console=console,
        )
        k8s_evidence = collector.collect(context["namespace"], context["deployment"])
        investigation.k8s_evidence = k8s_evidence
        _add_kubernetes_metadata(rollout_finding, k8s_evidence)
        _progress_for_evidence(console, k8s_evidence)

        progress.update(task_id, description="Correlating evidence...")
        _debug(console, debug, "Correlating evidence...")
        refine_rollout_timeout(rollout_finding, k8s_evidence)
        _debug(console, debug, "Determining root cause...")
        _debug_detected_root_cause(console, debug, rollout_finding)
        save_raw_evidence(k8s_evidence)
        _progress(console, "Investigation complete")
        investigation.duration_seconds = time.monotonic() - started_at

    return investigation


def save_raw_evidence(evidence: KubernetesEvidence, directory: Path | None = None) -> Path:
    output_dir = directory or Path(".jeffrey")
    output_dir.mkdir(parents=True, exist_ok=True)

    _write_result(output_dir / "deployment.txt", evidence.deployment_description)
    _write_result(output_dir / "pods.txt", evidence.pods_output)
    _write_result(output_dir / "events.txt", evidence.events_output)
    _write_many(output_dir / "pod_describe.txt", evidence.pod_descriptions)
    _write_many(output_dir / "logs.txt", evidence.pod_logs)
    _write_many(output_dir / "previous_logs.txt", evidence.pod_previous_logs)
    (output_dir / "commands.txt").write_text(
        "\n".join(result.command_text for result in evidence.executed_commands),
        encoding="utf-8",
    )
    return output_dir


def rollout_context_from_finding(finding: Finding) -> dict[str, str] | None:
    for evidence in finding.evidence:
        if evidence.startswith("Jenkins rollout command: "):
            command = evidence.removeprefix("Jenkins rollout command: ")
        elif evidence.startswith("Command: "):
            command = evidence.removeprefix("Command: ")
        else:
            continue

        context = parse_rollout_command(command)
        if context is not None:
            return context

    return None


def parse_rollout_command(command: str) -> dict[str, str] | None:
    try:
        tokens = shlex.split(command)
    except ValueError:
        return _parse_rollout_command_with_regex(command)

    namespace = None
    deployment = None
    timeout = None

    for index, token in enumerate(tokens):
        if token.startswith("--namespace="):
            namespace = token.split("=", 1)[1]
        elif token == "--namespace" and index + 1 < len(tokens):
            namespace = tokens[index + 1]
        elif token == "-n" and index + 1 < len(tokens):
            namespace = tokens[index + 1]
        elif token.startswith("--timeout="):
            timeout = token.split("=", 1)[1]
        elif token == "--timeout" and index + 1 < len(tokens):
            timeout = tokens[index + 1]

    for index in range(len(tokens) - 3):
        if tokens[index : index + 3] == ["rollout", "status", "deployment"]:
            deployment = tokens[index + 3]
            break

    if namespace is None or deployment is None:
        return _parse_rollout_command_with_regex(command)

    context = {"namespace": namespace, "deployment": deployment}
    if timeout is not None:
        context["timeout"] = timeout
    return context


def refine_rollout_timeout(finding: Finding, evidence: KubernetesEvidence) -> None:
    combined = "\n".join(_kubernetes_text_blocks(evidence))
    lower_combined = combined.lower()

    refinements = (
        (
            "CrashLoopBackOff",
            "Deployment rollout timed out because one or more pods are crashing after startup.",
            [
                "Inspect previous container logs",
                "Check application startup errors",
                "Check environment variables and secrets",
            ],
        ),
        (
            "ImagePullBackOff",
            "Deployment rollout timed out because Kubernetes could not pull the Docker image.",
            ["Check image tag", "Check registry credentials", "Check whether the image exists"],
        ),
        (
            "ErrImagePull",
            "Deployment rollout timed out because Kubernetes could not pull the Docker image.",
            ["Check image tag", "Check registry credentials", "Check whether the image exists"],
        ),
        (
            "OOMKilled",
            "Deployment rollout timed out because a container was killed due to memory limits.",
            [
                "Check memory limits",
                "Check recent memory usage",
                "Compare with the previous successful deployment",
            ],
        ),
        (
            "CreateContainerConfigError",
            (
                "Deployment rollout timed out because Kubernetes could not create the "
                "container configuration."
            ),
            [
                "Check ConfigMap references",
                "Check Secret references",
                "Check environment variable definitions",
            ],
        ),
        (
            "Readiness probe failed",
            "Deployment rollout timed out because new pods did not pass readiness checks.",
            [
                "Check readiness probe path and port",
                "Check application startup time",
                "Check pod logs and service dependencies",
            ],
        ),
        (
            "connection refused",
            (
                "Deployment rollout timed out because the application or one of its "
                "dependencies refused connections."
            ),
            [
                "Check dependent services",
                "Check ports and service names",
                "Check application startup logs",
            ],
        ),
        (
            "ModuleNotFoundError",
            (
                "Deployment rollout timed out because the application failed to start due to "
                "a missing Python module."
            ),
            [
                "Check requirements files",
                "Check Docker image build",
                "Check import path and startup command",
            ],
        ),
        (
            "permission denied",
            "Deployment rollout timed out because the application hit a permission error.",
            ["Check file permissions", "Check container user", "Check mounted volumes"],
        ),
    )

    for needle, root_cause, next_steps in refinements:
        if needle.lower() in lower_combined:
            finding.root_cause = root_cause
            finding.what_to_check_next = next_steps
            finding.evidence.extend(_important_evidence_lines(evidence, needle))
            finding.evidence = list(dict.fromkeys(finding.evidence))
            return

    finding.evidence.extend(_important_kubernetes_summary(evidence))
    finding.evidence = list(dict.fromkeys(finding.evidence))


def _add_kubernetes_metadata(finding: Finding, evidence: KubernetesEvidence) -> None:
    finding.metadata.update(
        {
            "has_k8s_evidence": "true",
            "namespace": evidence.namespace,
            "deployment": evidence.deployment,
            "deployment_description": _availability(evidence.deployment_description),
            "pods_checked": str(evidence.pods_checked),
            "events_checked": _availability(evidence.events_output),
            "previous_logs_checked": _previous_logs_availability(evidence),
            "executed_commands": str(len(evidence.executed_commands)),
        }
    )


def _rollout_timeout_finding(investigation: BuildInvestigation) -> Finding | None:
    for finding in investigation.findings:
        if finding.title == "Deployment rollout timed out":
            return finding
    return None


def _parse_rollout_command_with_regex(command: str) -> dict[str, str] | None:
    match = ROLLOUT_CONTEXT_PATTERN.search(command)
    if match is None:
        return None

    context = {
        "namespace": match.group("namespace"),
        "deployment": match.group("deployment"),
    }
    if match.group("timeout"):
        context["timeout"] = match.group("timeout")
    return context


def _kubernetes_text_blocks(evidence: KubernetesEvidence) -> list[str]:
    blocks = []
    for result in (
        evidence.deployment_description,
        evidence.pods_output,
        evidence.events_output,
        *evidence.pod_descriptions.values(),
        *evidence.pod_logs.values(),
        *evidence.pod_previous_logs.values(),
    ):
        if result is None:
            continue
        blocks.extend([result.stdout, result.stderr])
    return blocks


def _important_evidence_lines(evidence: KubernetesEvidence, needle: str) -> list[str]:
    lines = []
    for label, text in _labeled_kubernetes_text(evidence):
        for line in text.splitlines():
            if needle.lower() in line.lower():
                lines.append(f"{label}: {line.strip()}")
                if len(lines) >= 3:
                    return lines
    return lines


def _important_kubernetes_summary(evidence: KubernetesEvidence) -> list[str]:
    lines = []
    if evidence.deployment_description is not None:
        status = "available" if evidence.deployment_description.succeeded else "unavailable"
        lines.append(f"Kubernetes deployment description: {status}")
    if evidence.pods_output is not None:
        status = "available" if evidence.pods_output.succeeded else "unavailable"
        lines.append(f"Kubernetes pods output: {status}")
    if evidence.events_output is not None:
        status = "available" if evidence.events_output.succeeded else "unavailable"
        lines.append(f"Kubernetes events output: {status}")
    for error in evidence.command_errors[:3]:
        reason = _compact_error(error.stderr)
        lines.append(f"Kubernetes command failed: {error.command_text}: {reason}")
    return lines


def _availability(result: object | None) -> str:
    if result is None:
        return "unavailable"
    succeeded = getattr(result, "succeeded", False)
    return "available" if succeeded else "unavailable"


def _compact_error(stderr: str) -> str:
    lines = [line.strip() for line in stderr.splitlines() if line.strip()]
    if not lines:
        return "command failed"
    return lines[-1]


def _previous_logs_availability(evidence: KubernetesEvidence) -> str:
    if not evidence.pod_previous_logs:
        return "unavailable"
    if any(result.succeeded for result in evidence.pod_previous_logs.values()):
        return "available"
    return "unavailable"


def _labeled_kubernetes_text(evidence: KubernetesEvidence) -> list[tuple[str, str]]:
    labeled = []
    if evidence.deployment_description is not None:
        labeled.append(("Kubernetes", evidence.deployment_description.stdout))
        labeled.append(("Kubernetes", evidence.deployment_description.stderr))
    if evidence.pods_output is not None:
        labeled.append(("Kubernetes", evidence.pods_output.stdout))
        labeled.append(("Kubernetes", evidence.pods_output.stderr))
    if evidence.events_output is not None:
        labeled.append(("Kubernetes", evidence.events_output.stdout))
        labeled.append(("Kubernetes", evidence.events_output.stderr))
    for pod_name, result in evidence.pod_descriptions.items():
        labeled.append((f"Kubernetes pod {pod_name}", result.stdout))
        labeled.append((f"Kubernetes pod {pod_name}", result.stderr))
    for pod_name, result in evidence.pod_logs.items():
        labeled.append((f"Logs {pod_name}", result.stdout))
        labeled.append((f"Logs {pod_name}", result.stderr))
    for pod_name, result in evidence.pod_previous_logs.items():
        labeled.append((f"Previous logs {pod_name}", result.stdout))
        labeled.append((f"Previous logs {pod_name}", result.stderr))
    return labeled


def _progress_for_evidence(console: Console, evidence: KubernetesEvidence) -> None:
    _progress(console, "Deployment described")
    _progress(console, "Pods collected")
    _progress(console, "Events collected")
    if evidence.pod_logs or evidence.pod_previous_logs:
        _progress(console, "Pod logs collected")


def _progress(console: Console, message: str) -> None:
    console.print(f"[green]✓[/green] {message}")


def _debug(console: Console, enabled: bool, message: str) -> None:
    if enabled:
        console.print(f"[dim][DEBUG] {message}[/dim]")


def _debug_detected_root_cause(console: Console, enabled: bool, finding: Finding) -> None:
    if not enabled:
        return
    for evidence in finding.evidence:
        if any(
            marker in evidence
            for marker in (
                "CrashLoopBackOff",
                "ImagePullBackOff",
                "ErrImagePull",
                "OOMKilled",
                "ModuleNotFoundError",
            )
        ):
            console.print(f"[dim][DEBUG] {evidence.split(':', 1)[-1].strip()} detected[/dim]")
            return


def _write_result(path: Path, result: object | None) -> None:
    if result is None:
        path.write_text("", encoding="utf-8")
        return

    stdout = getattr(result, "stdout", "")
    stderr = getattr(result, "stderr", "")
    path.write_text(_join_output(stdout, stderr), encoding="utf-8")


def _write_many(path: Path, results: dict[str, object]) -> None:
    sections = []
    for name, result in results.items():
        stdout = getattr(result, "stdout", "")
        stderr = getattr(result, "stderr", "")
        sections.append(f"## {name}\n{_join_output(stdout, stderr)}")
    path.write_text("\n\n".join(sections), encoding="utf-8")


def _join_output(stdout: str, stderr: str) -> str:
    parts = []
    if stdout:
        parts.append(stdout)
    if stderr:
        parts.append(stderr)
    return "\n".join(parts)
