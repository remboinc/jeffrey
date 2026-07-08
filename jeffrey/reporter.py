from __future__ import annotations

from datetime import datetime
from pathlib import Path

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from jeffrey.models import Finding, ScanResult


def print_report(
    result: ScanResult,
    *,
    console: Console | None = None,
    show_all: bool = False,
    verbose: bool = False,
) -> None:
    console = console or Console()
    console.print("[bold]Jeffrey investigation report[/bold]")
    console.print()

    if result.is_success and not result.has_findings:
        _print_success(result, console, verbose=verbose)
        return

    if not result.has_findings:
        _print_unknown(result, console)
        return

    likely_root_cause = result.likely_root_cause
    if likely_root_cause is None:
        _print_unknown(result, console)
        return

    _print_finding(likely_root_cause, console, heading="Likely root cause")

    if result.warnings:
        console.print()
        console.print("[bold yellow]Warning:[/bold yellow]")
        for warning in result.warnings:
            console.print(warning)

    _print_log_insights(result, console)

    other_findings = result.findings[1:]
    if show_all and other_findings:
        console.print()
        console.print("[bold]All detected findings[/bold]")
        for finding in other_findings:
            console.print()
            _print_finding(finding, console, heading=finding.title)
    elif other_findings:
        console.print()
        console.print("[bold]Also detected:[/bold]")
        for finding in other_findings:
            console.print(f"- {finding.title}")

    _print_raw_evidence_path(result, console)

    if verbose:
        console.print()
        _print_compact_summary(result, console)


def _print_finding(finding: Finding, console: Console, *, heading: str) -> None:
    console.print(f"[bold]{heading}:[/bold]")
    console.print(finding.root_cause if finding.root_cause else finding.title)
    console.print()
    console.print("[bold]Stage:[/bold]")
    console.print(finding.stage or "Unknown")

    deployment = finding.metadata.get("deployment")
    namespace = finding.metadata.get("namespace")
    if deployment:
        console.print()
        console.print("[bold]Deployment:[/bold]")
        console.print(deployment)
    if namespace:
        console.print()
        console.print("[bold]Namespace:[/bold]")
        console.print(namespace)

    console.print()
    console.print("[bold]Evidence:[/bold]")
    for evidence in _default_evidence_lines(finding):
        console.print(f"- {evidence}")
    console.print()
    console.print("[bold]What to check next:[/bold]")
    for index, item in enumerate(_default_next_steps(finding), start=1):
        console.print(f"{index}. {item}")


def _print_unknown(result: ScanResult, console: Console) -> None:
    console.print("Jeffrey could not determine the root cause yet")
    console.print()

    table = Table.grid(expand=True)
    table.add_column()
    for line in result.last_lines:
        table.add_row(line)

    console.print(Panel(table, title="Last log lines", border_style="yellow"))


def _print_success(result: ScanResult, console: Console, *, verbose: bool) -> None:
    console.print("[bold green]Build finished successfully.[/bold green]")
    console.print("There is no failure root cause to investigate.")

    if not result.successful_steps:
        return

    console.print()
    console.print("[bold]Successful rollout steps:[/bold]")
    for step in result.successful_steps:
        console.print(f"- {step}")

    _print_raw_evidence_path(result, console)
    if verbose:
        console.print()
        _print_compact_summary(result, console)


def _print_collected_evidence(finding: Finding, console: Console) -> None:
    console.print("[bold]Collected evidence:[/bold]")
    deployment_description = finding.metadata.get("deployment_description", "unavailable")
    previous_logs_checked = finding.metadata.get("previous_logs_checked", "unavailable")
    console.print(f"- Deployment description: {deployment_description}")
    console.print(f"- Pods checked: {finding.metadata.get('pods_checked', '0')}")
    console.print(f"- Events checked: {finding.metadata.get('events_checked', 'unavailable')}")
    console.print(f"- Previous logs checked: {previous_logs_checked}")


def _print_compact_summary(result: ScanResult, console: Console) -> None:
    finding = result.likely_root_cause
    metadata = finding.metadata if finding is not None else {}
    evidence = result.k8s_evidence

    console.print("[bold]Investigation summary[/bold]")
    console.print()
    console.print("[bold]Build:[/bold]")
    console.print(result.build_status or result.status.upper())
    console.print()
    console.print("[bold]Stage:[/bold]")
    console.print(finding.stage if finding is not None and finding.stage else "Unknown")
    console.print()
    console.print("[bold]Deployment:[/bold]")
    console.print(metadata.get("deployment") or _successful_deployment(result) or "Unknown")
    console.print()
    console.print("[bold]Namespace:[/bold]")
    console.print(metadata.get("namespace") or "Unknown")
    console.print()
    console.print("[bold]Pods investigated:[/bold]")
    console.print(str(evidence.pods_checked if evidence is not None else 0))
    console.print()
    console.print("[bold]Selector:[/bold]")
    console.print(metadata.get("selector") or "Unknown")
    console.print()
    console.print("[bold]Correlated events found:[/bold]")
    console.print(metadata.get("correlated_events_found", "0"))
    console.print()
    console.print("[bold]Unrelated namespace events ignored:[/bold]")
    console.print(metadata.get("unrelated_namespace_events_ignored", "0"))
    console.print()
    console.print("[bold]Events collected:[/bold]")
    console.print(_yes_no(evidence is not None and evidence.namespace_events_output is not None))
    console.print()
    console.print("[bold]Previous logs:[/bold]")
    console.print(_yes_no(evidence is not None and evidence.previous_logs_checked))
    console.print()
    console.print("[bold]Duration:[/bold]")
    duration = result.duration_seconds if result.duration_seconds is not None else 0
    console.print(f"{duration:.1f} seconds")


def _print_raw_evidence_path(result: ScanResult, console: Console) -> None:
    if result.raw_evidence_dir is None:
        return
    console.print()
    console.print("[bold]Raw evidence saved to:[/bold]")
    console.print(f"{result.raw_evidence_dir}/")


def _default_evidence_lines(finding: Finding) -> list[str]:
    lines = []
    timeout = finding.metadata.get("timeout")
    for evidence in finding.evidence:
        if evidence.startswith("Jenkins rollout command: "):
            if timeout:
                lines.append(f"Jenkins rollout command timed out after {timeout}")
            else:
                lines.append("Jenkins rollout command timed out")
            continue
        if _is_default_noise(evidence):
            continue
        lines.append(evidence)

    if finding.metadata.get("has_k8s_evidence") == "true":
        deployment = finding.metadata.get("deployment", "deployment")
        if _has_correlated_failure_evidence(lines):
            lines.append(
                f"Correlated Kubernetes evidence was collected for deployment {deployment}"
            )
        else:
            lines.append(
                "No correlated Kubernetes pod failure was found in current cluster state."
            )
        if finding.metadata.get("fallback_pod_matching_used") == "true":
            lines.append("Pod selector lookup failed; fallback pod name matching was used")
        if len(lines) <= 2:
            lines.append("No deeper Kubernetes cause was detected")

    return list(dict.fromkeys(lines))[:5]


def _default_next_steps(finding: Finding) -> list[str]:
    if finding.metadata.get("has_k8s_evidence") != "true":
        return finding.what_to_check_next[:3]

    next_steps = []
    first_pod = finding.metadata.get("first_pod")
    if int(finding.metadata.get("pods_checked", "0")) > 0:
        next_steps.append("Open .jeffrey/pods.txt")
    if first_pod:
        next_steps.append(f"Open .jeffrey/pod_{_safe_filename(first_pod)}_logs.txt")
    next_steps.append("Re-run with --debug for full investigation trace")
    return next_steps[:3]


def _has_correlated_failure_evidence(lines: list[str]) -> bool:
    markers = (
        "CrashLoopBackOff",
        "ImagePullBackOff",
        "ErrImagePull",
        "OOMKilled",
        "CreateContainerConfigError",
        "Readiness probe failed",
        "Liveness probe failed",
        "ModuleNotFoundError",
        "permission denied",
        "connection refused",
    )
    return any(any(marker in line for marker in markers) for line in lines)


def _is_default_noise(evidence: str) -> bool:
    noisy_fragments = (
        "Kubernetes deployment description:",
        "Kubernetes pods output:",
        "Kubernetes events output:",
        "Kubernetes namespace events output:",
        "Kubernetes command failed:",
        "Kubernetes evidence was collected",
        "previous terminated container",
        "not found",
    )
    return any(fragment in evidence for fragment in noisy_fragments)


def _print_log_insights(result: ScanResult, console: Console) -> None:
    evidence = result.k8s_evidence
    if evidence is None:
        return

    console.print()
    console.print("[bold]Log insights:[/bold]")
    for insight in evidence.log_insights[:3]:
        pod_ref = f"pod/{insight.pod_name}"
        source = insight.source.replace("_", " ")
        if insight.matched_pattern in {"clean logs", "no matched pods"}:
            console.print(f"- {insight.message}")
        else:
            console.print(f"- {pod_ref} {source}: {insight.message}")


def save_markdown_report(result: ScanResult, path: Path) -> None:
    finding = result.likely_root_cause
    evidence = result.k8s_evidence
    metadata = finding.metadata if finding is not None else {}

    lines = [
        "# Jeffrey Investigation Report",
        "",
        f"Date: {datetime.now().isoformat(timespec='seconds')}",
        "",
        f"Build: {result.build_status or result.status.upper()}",
        "",
        f"Deployment: {metadata.get('deployment') or _successful_deployment(result) or 'Unknown'}",
        "",
        f"Namespace: {metadata.get('namespace') or 'Unknown'}",
        "",
        "## Likely root cause",
        "",
        finding.root_cause if finding is not None else "No failure root cause detected.",
        "",
        "## Evidence",
        "",
    ]

    if finding is not None:
        lines.extend(f"- {item}" for item in finding.evidence)
    else:
        lines.append("- Build finished successfully.")

    lines.extend(["", "## Executed commands", ""])
    if evidence is not None and evidence.executed_commands:
        lines.extend(f"- `{command.command_text}`" for command in evidence.executed_commands)
    else:
        lines.append("- None")

    lines.extend(["", "## Pod status", ""])
    pods_output = evidence.pods_output.stdout if evidence and evidence.pods_output else ""
    lines.append(_markdown_block(pods_output))

    lines.extend(["", "## Events", ""])
    events_output = evidence.events_output.stdout if evidence and evidence.events_output else ""
    lines.append(_markdown_block(events_output))

    lines.extend(["", "## Previous logs", ""])
    if evidence is not None and evidence.pod_previous_logs:
        for pod_name, result_item in evidence.pod_previous_logs.items():
            lines.append(f"### {pod_name}")
            lines.append("")
            lines.append(_markdown_block(result_item.stdout or result_item.stderr))
    else:
        lines.append("- None")

    lines.extend(["", "## Recommended next steps", ""])
    if finding is not None:
        lines.extend(f"{index}. {item}" for index, item in enumerate(finding.what_to_check_next, 1))
    else:
        lines.append("1. No action required.")

    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def _successful_deployment(result: ScanResult) -> str | None:
    if not result.successful_rollouts:
        return None
    return result.successful_rollouts[-1].name


def _yes_no(value: bool) -> str:
    return "Yes" if value else "No"


def _markdown_block(text: str) -> str:
    if not text:
        return "- Not available"
    return f"```text\n{text.rstrip()}\n```"


def _safe_filename(value: str) -> str:
    return "".join(
        character if character.isalnum() or character in "_.-" else "_"
        for character in value
    )
