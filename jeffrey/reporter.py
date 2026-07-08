from __future__ import annotations

import re
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse

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

    _print_finding(likely_root_cause, result, console, heading="Likely root cause")
    _print_kubernetes_signal(result, console)
    _print_relevant_log_excerpts(result, console)
    _print_jeffrey_conclusion(result, console)
    _print_manual_follow_up(result, console)

    if result.warnings:
        console.print()
        console.print("[bold yellow]Warning:[/bold yellow]")
        for warning in result.warnings:
            console.print(warning)

    other_findings = result.findings[1:]
    if show_all and other_findings:
        console.print()
        console.print("[bold]All detected findings[/bold]")
        for finding in other_findings:
            console.print()
            _print_finding(finding, result, console, heading=finding.title)
    elif other_findings:
        console.print()
        console.print("[bold]Also detected:[/bold]")
        for finding in other_findings:
            console.print(f"- {finding.title}")

    _print_raw_evidence_path(result, console)

    if verbose:
        console.print()
        _print_compact_summary(result, console)


def _print_finding(
    finding: Finding,
    result: ScanResult,
    console: Console,
    *,
    heading: str,
) -> None:
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
    for evidence in _default_evidence_lines(finding, result):
        console.print(f"- {evidence}")


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


def _default_evidence_lines(finding: Finding, result: ScanResult) -> list[str]:
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

    signals = _kubernetes_signal_insights(result)
    if signals:
        lines.extend(_evidence_from_kubernetes_signals(signals))
    elif finding.metadata.get("has_k8s_evidence") == "true":
        lines.append("No correlated Kubernetes pod failure was found in current cluster state.")

    if finding.metadata.get("has_k8s_evidence") == "true":
        if finding.metadata.get("fallback_pod_matching_used") == "true":
            lines.append("Pod selector lookup failed; fallback pod name matching was used")
        if len(lines) <= 2:
            lines.append("No deeper Kubernetes cause was detected")

    return list(dict.fromkeys(lines))[:5]


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


def _print_kubernetes_signal(result: ScanResult, console: Console) -> None:
    insights = _kubernetes_signal_insights(result)
    if not insights:
        return

    console.print()
    console.print("[bold]Kubernetes signal:[/bold]")
    for insight in insights[:3]:
        console.print(f"- {_format_kubernetes_signal(insight)}")


def _print_relevant_log_excerpts(result: ScanResult, console: Console) -> None:
    excerpts = _relevant_log_excerpts(result)
    if not excerpts:
        return

    console.print()
    console.print("[bold]Relevant log excerpts:[/bold]")
    for excerpt in excerpts[:3]:
        pod_ref = f"pod/{excerpt.pod_name}"
        source = excerpt.source.replace("_", " ")
        if excerpt.score <= 0:
            console.print(f"- {excerpt.message}")
        else:
            console.print(f"- [{excerpt.label}] {pod_ref} {source}: {excerpt.message}")
    if len([excerpt for excerpt in excerpts if excerpt.score > 0]) > 3:
        console.print()
        console.print("[bold]More log excerpts saved to:[/bold]")
        console.print(f"{result.raw_evidence_dir or '.jeffrey'}/")


def _print_jeffrey_conclusion(result: ScanResult, console: Console) -> None:
    finding = result.likely_root_cause
    if finding is None:
        return

    console.print()
    console.print("[bold]Jeffrey conclusion:[/bold]")
    for line in _jeffrey_conclusion_lines(result):
        console.print(f"- {line}")


def _print_manual_follow_up(result: ScanResult, console: Console) -> None:
    follow_up = _manual_follow_up_lines(result)
    if not follow_up:
        return

    console.print()
    console.print("[bold]Manual follow-up:[/bold]")
    for line in follow_up:
        console.print(f"- {line}")


def _kubernetes_signal_insights(result: ScanResult):
    evidence = result.k8s_evidence
    if evidence is None:
        return []
    ignored = {"no correlated warning events"}
    return [
        insight
        for insight in evidence.log_insights
        if insight.source in {"describe", "events"} and insight.matched_pattern not in ignored
    ]


def _application_log_insights(result: ScanResult):
    evidence = result.k8s_evidence
    if evidence is None:
        return []
    return [
        insight
        for insight in evidence.log_insights
        if insight.source in {"logs", "previous_logs"}
    ]


def _relevant_log_excerpts(result: ScanResult):
    evidence = result.k8s_evidence
    if evidence is None:
        return []
    return evidence.log_excerpts


def _evidence_from_kubernetes_signals(insights: list) -> list[str]:
    lines = []
    for insight in insights[:2]:
        if insight.matched_pattern.lower() == "readiness probe failed":
            lines.append(f"Kubernetes readiness probe failed for pod/{insight.pod_name}")
            endpoint = _readiness_endpoint_summary(insight.message)
            if endpoint:
                lines.append(endpoint)
            continue
        lines.append(f"Kubernetes signal: {_format_kubernetes_signal(insight)}")
    return lines


def _format_kubernetes_signal(insight) -> str:
    message = insight.message.strip()
    lower_message = message.lower()
    if insight.matched_pattern.lower() == "readiness probe failed":
        detail = _probe_failure_detail(message)
        return f"readiness probe failed: {detail}"
    if "crashloopbackoff" in lower_message:
        return f"CrashLoopBackOff for pod/{insight.pod_name}"
    return message


def _probe_failure_detail(message: str) -> str:
    if "context deadline exceeded" in message.lower():
        return "context deadline exceeded"
    if "connection refused" in message.lower() or "refused" in message.lower():
        return "connection refused"
    if ":" in message:
        return message.split(":", 1)[1].strip()
    return message


def _readiness_endpoint_summary(message: str) -> str | None:
    parsed_url = _first_url(message)
    if parsed_url is None:
        return None
    path = parsed_url.path or "/"
    if parsed_url.query:
        path = f"{path}?{parsed_url.query}"
    port = parsed_url.port
    lower_message = message.lower()
    if "context deadline exceeded" in lower_message:
        outcome = "timed out"
    elif "connection refused" in lower_message or "refused" in lower_message:
        outcome = "refused connection"
    else:
        outcome = "failed"
    if port is None:
        return f"Readiness endpoint {path} {outcome}"
    return f"Readiness endpoint {path} on port {port} {outcome}"


def _first_url(message: str):
    match = re.search(r"https?://[^\s\"]+", message)
    if match is None:
        return None
    return urlparse(match.group(0))


def _jeffrey_conclusion_lines(result: ScanResult) -> list[str]:
    finding = result.likely_root_cause
    evidence = result.k8s_evidence
    if finding is None:
        return []

    lines = [_root_cause_conclusion(finding.root_cause)]
    signals = _kubernetes_signal_insights(result)
    if signals:
        lines.append(_readiness_behavior_conclusion(signals))
        lines.append("Jeffrey checked Kubernetes events and pod describe output.")
    elif evidence is not None:
        lines.append("Jeffrey checked Kubernetes deployment, pod and event evidence.")

    app_lines = _application_log_conclusion_lines(result)
    lines.extend(app_lines)

    if result.warnings:
        lines.append("Current cluster state may differ from the failed build state.")

    return list(dict.fromkeys(line for line in lines if line))


def _root_cause_conclusion(root_cause: str) -> str:
    lower_root = root_cause.lower()
    if "readiness" in lower_root or "not become ready" in lower_root:
        return "The pod did not become ready during rollout."
    if "missing python module" in lower_root:
        return "The application failed to start because a Python module was missing."
    if "crashing" in lower_root:
        return "One or more pods were crashing after startup."
    return root_cause.rstrip(".") + "."


def _readiness_behavior_conclusion(insights: list) -> str:
    text = "\n".join(insight.message.lower() for insight in insights)
    refused = "connection refused" in text or "refused" in text
    timed_out = "context deadline exceeded" in text or "timeout" in text
    if refused and timed_out:
        return (
            "Kubernetes could reach the pod IP, but the readiness endpoint did not "
            "respond reliably."
        )
    if refused:
        return "The readiness endpoint refused connections."
    if timed_out:
        return "The readiness endpoint timed out before responding."
    return "Kubernetes reported a correlated pod readiness failure."


def _application_log_conclusion_lines(result: ScanResult) -> list[str]:
    excerpts = _relevant_log_excerpts(result)
    lines = []
    if any(excerpt.matched_pattern == "clean logs" for excerpt in excerpts):
        lines.append("No known application startup errors were found in collected logs.")
    if any("unavailable" in excerpt.matched_pattern for excerpt in excerpts):
        lines.append("Application logs could not be collected.")
    if any(
        excerpt.score > 0 and excerpt.label not in {"STACK", "WARNING"}
        for excerpt in excerpts
    ):
        lines.append("Application logs contained known error patterns.")
    if any(excerpt.matched_pattern == "previous_logs unavailable" for excerpt in excerpts):
        lines.append("Previous logs were not available.")
    return lines


def _manual_follow_up_lines(result: ScanResult) -> list[str]:
    evidence = result.k8s_evidence
    if evidence is None:
        return []

    lines = []
    if evidence.environment is not None and not evidence.environment.kubectl_found:
        lines.append("Run Jeffrey from a machine with kubectl access.")
    if not evidence.selected_pods:
        lines.append("Check the deployment selector.")
    if any(
        excerpt.matched_pattern == "logs unavailable"
        for excerpt in _relevant_log_excerpts(result)
    ):
        lines.append("Check pod logs manually because Kubernetes did not return logs.")
    return lines


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
