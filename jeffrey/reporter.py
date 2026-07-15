from __future__ import annotations

import re
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from jeffrey import messages as msg
from jeffrey.kubernetes import resource_forbidden
from jeffrey.models import Finding, ScanResult


def print_report(
    result: ScanResult,
    *,
    console: Console | None = None,
    show_all: bool = False,
    verbose: bool = False,
) -> None:
    console = console or Console()
    console.print(f"[bold]{msg.REPORT_TITLE}[/bold]")
    console.print()

    if result.is_success and not result.has_findings:
        _print_success(result, console, verbose=verbose)
        return

    if result.is_incomplete and not result.has_findings:
        _print_incomplete(result, console)
        return

    if not result.has_findings:
        _print_unknown(result, console)
        return

    likely_root_cause = result.likely_root_cause
    if likely_root_cause is None:
        _print_unknown(result, console)
        return

    _print_finding(
        likely_root_cause,
        result,
        console,
        heading=_finding_heading(result),
    )
    _print_kubernetes_signal(result, console)
    _print_relevant_log_excerpts(result, console)
    _print_jeffrey_conclusion(result, console)
    _print_possible_explanations(result, console)
    _print_manual_follow_up(result, console)

    if result.warnings:
        console.print()
        console.print(f"[bold yellow]{msg.SECTION_WARNING}:[/bold yellow]")
        for warning in result.warnings:
            console.print(warning)

    other_findings = result.findings[1:]
    if show_all and other_findings:
        console.print()
        console.print(f"[bold]{msg.SECTION_ALL_DETECTED_FINDINGS}[/bold]")
        for finding in other_findings:
            console.print()
            _print_finding(finding, result, console, heading=finding.title)
    elif other_findings:
        console.print()
        console.print(f"[bold]{msg.SECTION_ALSO_DETECTED}:[/bold]")
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
    console.print(_finding_summary_text(finding, result, heading))
    console.print()
    console.print(f"[bold]{msg.SECTION_STAGE}:[/bold]")
    console.print(finding.stage or msg.UNKNOWN_VALUE)

    deployment = finding.metadata.get("deployment")
    job = finding.metadata.get("job")
    namespace = finding.metadata.get("namespace")
    if deployment:
        console.print()
        console.print(f"[bold]{msg.SECTION_DEPLOYMENT}:[/bold]")
        console.print(deployment)
    if job:
        console.print()
        console.print(f"[bold]{msg.SECTION_JOB}:[/bold]")
        console.print(job)
    if namespace:
        console.print()
        console.print(f"[bold]{msg.SECTION_NAMESPACE}:[/bold]")
        console.print(namespace)

    console.print()
    console.print(f"[bold]{msg.SECTION_EVIDENCE}:[/bold]")
    for evidence in _default_evidence_lines(finding, result):
        console.print(f"- {evidence}")


def _finding_heading(result: ScanResult) -> str:
    if _has_confirmed_root_cause(result):
        return msg.SECTION_LIKELY_ROOT_CAUSE
    return msg.SECTION_PRIMARY_FINDING


def _finding_summary_text(finding: Finding, result: ScanResult, heading: str) -> str:
    if heading == msg.SECTION_LIKELY_ROOT_CAUSE:
        return finding.root_cause if finding.root_cause else finding.title

    if result.job_context is not None:
        job = result.job_context.job
        if _job_completed_now(result):
            return f"Jenkins timed out while waiting for Kubernetes Job {job} to complete."
        if _job_running_with_clean_logs(result):
            return f"Kubernetes Job {job} did not complete before the Jenkins timeout."
        return f"Jenkins timed out while waiting for Kubernetes Job {job} to complete."

    deployment = finding.metadata.get("deployment")
    if deployment:
        return f"Jenkins timed out while waiting for deployment {deployment} to roll out."

    return finding.root_cause if finding.root_cause else finding.title


def _print_unknown(result: ScanResult, console: Console) -> None:
    console.print(msg.UNKNOWN_ROOT_CAUSE)
    console.print()
    _print_last_lines(result, console)


def _print_incomplete(result: ScanResult, console: Console) -> None:
    console.print(msg.INCOMPLETE_LOG)
    console.print(msg.INCOMPLETE_LOG_ANALYZED)
    console.print()
    _print_last_lines(result, console)


def _print_last_lines(result: ScanResult, console: Console) -> None:
    table = Table.grid(expand=True)
    table.add_column()
    for line in result.last_lines:
        table.add_row(line)

    console.print(Panel(table, title=msg.LAST_LOG_LINES_TITLE, border_style="yellow"))


def _print_success(result: ScanResult, console: Console, *, verbose: bool) -> None:
    console.print(f"[bold green]{msg.BUILD_SUCCESS}[/bold green]")
    console.print(msg.NO_FAILURE_TO_INVESTIGATE)

    if not result.successful_steps:
        return

    console.print()
    console.print(f"[bold]{msg.SECTION_SUCCESSFUL_ROLLOUT_STEPS}:[/bold]")
    for step in result.successful_steps:
        console.print(f"- {step}")

    _print_raw_evidence_path(result, console)
    if verbose:
        console.print()
        _print_compact_summary(result, console)


def _print_collected_evidence(finding: Finding, console: Console) -> None:
    console.print(f"[bold]{msg.SECTION_COLLECTED_EVIDENCE}:[/bold]")
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

    console.print(f"[bold]{msg.SECTION_INVESTIGATION_SUMMARY}[/bold]")
    console.print()
    console.print(f"[bold]{msg.SECTION_BUILD}:[/bold]")
    console.print(result.build_status or result.status.upper())
    console.print()
    console.print(f"[bold]{msg.SECTION_STAGE}:[/bold]")
    console.print(finding.stage if finding is not None and finding.stage else msg.UNKNOWN_VALUE)
    console.print()
    console.print(f"[bold]{msg.SECTION_DEPLOYMENT}:[/bold]")
    console.print(metadata.get("deployment") or _successful_deployment(result) or msg.UNKNOWN_VALUE)
    console.print()
    console.print(f"[bold]{msg.SECTION_NAMESPACE}:[/bold]")
    console.print(metadata.get("namespace") or msg.UNKNOWN_VALUE)
    console.print()
    console.print(f"[bold]{msg.SECTION_PODS_INVESTIGATED}:[/bold]")
    console.print(str(evidence.pods_checked if evidence is not None else 0))
    console.print()
    console.print(f"[bold]{msg.SECTION_SELECTOR}:[/bold]")
    console.print(metadata.get("selector") or msg.UNKNOWN_VALUE)
    console.print()
    console.print(f"[bold]{msg.SECTION_CORRELATED_EVENTS_FOUND}:[/bold]")
    console.print(metadata.get("correlated_events_found", "0"))
    console.print()
    console.print(f"[bold]{msg.SECTION_UNRELATED_NAMESPACE_EVENTS_IGNORED}:[/bold]")
    console.print(metadata.get("unrelated_namespace_events_ignored", "0"))
    console.print()
    console.print(f"[bold]{msg.SECTION_EVENTS_COLLECTED}:[/bold]")
    console.print(_yes_no(evidence is not None and evidence.namespace_events_output is not None))
    console.print()
    console.print(f"[bold]{msg.SECTION_PREVIOUS_LOGS}:[/bold]")
    console.print(_yes_no(evidence is not None and evidence.previous_logs_checked))
    console.print()
    console.print(f"[bold]{msg.SECTION_DURATION}:[/bold]")
    duration = result.duration_seconds if result.duration_seconds is not None else 0
    console.print(f"{duration:.1f} seconds")


def _print_raw_evidence_path(result: ScanResult, console: Console) -> None:
    if result.raw_evidence_dir is None:
        return
    console.print()
    console.print(f"[bold]{msg.SECTION_RAW_EVIDENCE}:[/bold]")
    console.print(f"{result.raw_evidence_dir}/")


def _default_evidence_lines(finding: Finding, result: ScanResult) -> list[str]:
    lines = []
    timeout = finding.metadata.get("timeout")
    for evidence in finding.evidence:
        if evidence.startswith("Jenkins rollout command: "):
            if timeout:
                lines.append(msg.jenkins_rollout_timed_out(timeout))
            else:
                lines.append(msg.jenkins_rollout_timed_out(None))
            continue
        if _is_default_noise(evidence):
            continue
        lines.append(evidence)

    signals = _kubernetes_signal_insights(result)
    if _kubernetes_access_denied(result):
        namespace = finding.metadata.get("namespace", msg.UNKNOWN_VALUE)
        lines.append(msg.kubernetes_access_denied(namespace))
    elif signals:
        lines.extend(_evidence_from_kubernetes_signals(signals))
    elif finding.metadata.get("has_k8s_evidence") == "true":
        lines.append(msg.no_correlated_kubernetes_failure())

    if finding.metadata.get("has_k8s_evidence") == "true":
        if (
            finding.metadata.get("fallback_pod_matching_used") == "true"
            and not _kubernetes_access_denied(result)
        ):
            lines.append(msg.fallback_pod_matching_used())
        if len(lines) <= 2:
            lines.append(msg.no_deeper_kubernetes_cause())

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
    if result.job_evidence is not None:
        _print_job_kubernetes_signal(result, console)
        return
    insights = _kubernetes_signal_insights(result)
    if not insights:
        return

    console.print()
    console.print(f"[bold]{msg.SECTION_KUBERNETES_SIGNAL}:[/bold]")
    for insight in insights[:3]:
        console.print(f"- {_format_kubernetes_signal(insight)}")


def _print_relevant_log_excerpts(result: ScanResult, console: Console) -> None:
    excerpts = _relevant_log_excerpts(result)
    if not excerpts:
        return

    console.print()
    console.print(f"[bold]{msg.SECTION_RELEVANT_LOG_EXCERPTS}:[/bold]")
    for excerpt in excerpts[:3]:
        pod_ref = f"pod/{excerpt.pod_name}"
        source = excerpt.source.replace("_", " ")
        if excerpt.score <= 0:
            console.print(f"- {excerpt.message}")
        else:
            console.print(f"- [{excerpt.label}] {pod_ref} {source}: {excerpt.message}")
    if len([excerpt for excerpt in excerpts if excerpt.score > 0]) > 3:
        console.print()
        console.print(f"[bold]{msg.SECTION_MORE_LOG_EXCERPTS}:[/bold]")
        console.print(f"{result.raw_evidence_dir or '.jeffrey'}/")


def _print_jeffrey_conclusion(result: ScanResult, console: Console) -> None:
    finding = result.likely_root_cause
    if finding is None:
        return

    console.print()
    console.print(f"[bold]{msg.SECTION_JEFFREY_CONCLUSION}:[/bold]")
    for line in _jeffrey_conclusion_lines(result):
        console.print(f"- {line}")


def _print_possible_explanations(result: ScanResult, console: Console) -> None:
    explanations = _possible_explanations(result)
    if not explanations:
        return

    console.print()
    console.print(f"[bold]{msg.SECTION_POSSIBLE_EXPLANATIONS}:[/bold]")
    for line in explanations:
        console.print(f"- {line}")


def _print_manual_follow_up(result: ScanResult, console: Console) -> None:
    follow_up = _manual_follow_up_lines(result)
    if not follow_up:
        return

    console.print()
    console.print(f"[bold]{msg.SECTION_MANUAL_FOLLOW_UP}:[/bold]")
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
    if result.job_evidence is not None:
        return result.job_evidence.log_excerpts
    evidence = result.k8s_evidence
    if evidence is None:
        return []
    return evidence.log_excerpts


def _evidence_from_kubernetes_signals(insights: list) -> list[str]:
    lines = []
    for insight in insights[:2]:
        if insight.matched_pattern.lower() == "readiness probe failed":
            lines.append(msg.kubernetes_readiness_failed(insight.pod_name))
            endpoint = _readiness_endpoint_summary(insight.message)
            if endpoint:
                lines.append(endpoint)
            continue
        lines.append(msg.kubernetes_signal(_format_kubernetes_signal(insight)))
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
        return msg.readiness_endpoint(path, None, outcome)
    return msg.readiness_endpoint(path, port, outcome)


def _first_url(message: str):
    match = re.search(r"https?://[^\s\"]+", message)
    if match is None:
        return None
    return urlparse(match.group(0))


def _jeffrey_conclusion_lines(result: ScanResult) -> list[str]:
    finding = result.likely_root_cause
    if finding is None:
        return []
    if result.job_evidence is not None:
        return _job_conclusion_lines(result)

    lines = [_root_cause_conclusion(finding.root_cause)]
    if _kubernetes_access_denied(result):
        lines.append(msg.kubernetes_access_denied_conclusion())
    signals = _kubernetes_signal_insights(result)
    if signals:
        lines.append(_readiness_behavior_conclusion(signals))

    if result.warnings:
        lines.append(msg.cluster_state_may_differ())

    return list(dict.fromkeys(line for line in lines if line))


def _root_cause_conclusion(root_cause: str) -> str:
    lower_root = root_cause.lower()
    if "readiness" in lower_root or "not become ready" in lower_root:
        return msg.readiness_conclusion()
    if "missing python module" in lower_root:
        return msg.missing_module_conclusion()
    if "crashing" in lower_root:
        return msg.crashing_conclusion()
    return msg.root_cause_conclusion(root_cause)


def _readiness_behavior_conclusion(insights: list) -> str:
    text = "\n".join(insight.message.lower() for insight in insights)
    refused = "connection refused" in text or "refused" in text
    timed_out = "context deadline exceeded" in text or "timeout" in text
    if refused and timed_out:
        return msg.readiness_endpoint_unreliable()
    if refused:
        return msg.readiness_endpoint_refused()
    if timed_out:
        return msg.readiness_endpoint_timed_out()
    return msg.correlated_readiness_failure()


def _manual_follow_up_lines(result: ScanResult) -> list[str]:
    if result.job_evidence is not None:
        lines = []
        if _job_access_denied(result):
            lines.append(msg.run_with_jenkins_kube_access())
            lines.append(msg.request_kubernetes_read_access())
        elif not result.job_evidence.selected_pods:
            lines.append(msg.check_deployment_selector())
        if any(
            excerpt.matched_pattern == "logs unavailable"
            for excerpt in _relevant_log_excerpts(result)
        ):
            lines.append(msg.check_pod_logs_manually())
        return lines

    evidence = result.k8s_evidence
    if evidence is None:
        return []

    lines = []
    if evidence.environment is not None and not evidence.environment.kubectl_found:
        lines.append(msg.run_with_kubectl_access())
    if _kubernetes_access_denied(result):
        lines.append(msg.run_with_jenkins_kube_access())
        lines.append(msg.request_kubernetes_read_access())
    elif not evidence.selected_pods:
        lines.append(msg.check_deployment_selector())
    if any(
        excerpt.matched_pattern == "logs unavailable"
        for excerpt in _relevant_log_excerpts(result)
    ):
        lines.append(msg.check_pod_logs_manually())
    return lines


def _kubernetes_access_denied(result: ScanResult) -> bool:
    evidence = result.k8s_evidence
    if evidence is None:
        return False
    return any(
        resource_forbidden(command)
        for command in (evidence.deployment_json, evidence.deployment_description)
    )


def _job_access_denied(result: ScanResult) -> bool:
    evidence = result.job_evidence
    if evidence is None:
        return False
    return any(
        resource_forbidden(command)
        for command in (evidence.job_json, evidence.job_description)
    )


def _print_job_kubernetes_signal(result: ScanResult, console: Console) -> None:
    evidence = result.job_evidence
    if evidence is None:
        return
    console.print()
    console.print(f"[bold]{msg.SECTION_KUBERNETES_SIGNAL}:[/bold]")
    if _job_completed_now(result):
        console.print(f"- {msg.jenkins_observed_job_incomplete()}")
        console.print(f"- {msg.current_job_pod_status_completed()}")
        console.print(f"- {msg.current_job_state_may_differ()}")
        return

    console.print(f"- {msg.job_did_not_complete()}")
    console.print(f"- {msg.pods_matched(len(evidence.selected_pods))}")
    for status in list(dict.fromkeys(evidence.pod_statuses.values()))[:2]:
        console.print(f"- {msg.pod_status(status)}")


def _job_conclusion_lines(result: ScanResult) -> list[str]:
    evidence = result.job_evidence
    timeout = result.job_context.timeout if result.job_context is not None else None
    completed_now = _job_completed_now(result)
    if completed_now:
        lines = [msg.job_conclusion_waited_but_timed_out(timeout)]
        lines.append(msg.job_pod_completed_now())
        if _job_logs_collected_clean(result):
            lines.append(msg.current_job_logs_clean())
        lines.append(msg.job_completed_after_timeout_explanation())
    else:
        lines = [msg.job_conclusion_waited(timeout)]

    if completed_now:
        pass
    elif evidence is not None and any(
        status == "Running" for status in evidence.pod_statuses.values()
    ):
        lines.append(msg.job_pod_still_running())
        lines.append(msg.job_did_not_fail_timed_out())
        lines.append(msg.job_likely_running_or_blocked())
    elif evidence is not None and any(
        status in {"Failed", "Error", "CrashLoopBackOff", "OOMKilled"}
        for status in evidence.pod_statuses.values()
    ):
        lines.append(msg.job_pod_failed_before_completion())
        if _has_suspicious_log_excerpts(result):
            lines.extend(_job_suspicious_log_conclusions(result))
            lines.append(msg.job_log_excerpts_point_to_failure())
    elif result.job_context is not None:
        lines.append(msg.job_pod_logs_not_analyzed(result.job_context.job))
    if result.warnings and not completed_now:
        lines.append(msg.cluster_state_may_differ())
    return list(dict.fromkeys(line for line in lines if line))


def _job_suspicious_log_conclusions(result: ScanResult) -> list[str]:
    lines = []
    labels = {excerpt.label for excerpt in _relevant_log_excerpts(result)}
    if "PANIC" in labels:
        lines.append(msg.job_logs_show_panic())
        lines.append(msg.job_panic_timeout_explanation())
    if "CONNECTION_REFUSED" in labels:
        lines.append(msg.job_logs_show_refused_connections())
        lines.append(msg.job_dependency_unavailable())
    return lines


def _has_suspicious_log_excerpts(result: ScanResult) -> bool:
    return any(
        excerpt.score > 0 and excerpt.label not in {"STACK", "WARNING"}
        for excerpt in _relevant_log_excerpts(result)
    )


def _possible_explanations(result: ScanResult) -> tuple[str, ...]:
    if _has_strong_explicit_root_cause(result):
        return ()
    if result.job_evidence is not None and _job_completed_now(result):
        return msg.possible_completed_after_job_timeout()
    if result.job_evidence is not None and _job_running_with_clean_logs(result):
        return msg.possible_long_running_job()
    if result.k8s_evidence is not None and _readiness_timeout_with_clean_logs(result):
        return msg.possible_readiness_timeout()
    return ()


def _job_completed_now(result: ScanResult) -> bool:
    evidence = result.job_evidence
    if evidence is None:
        return False
    return any(
        _normalize_job_pod_status(status) in {"completed", "succeeded"}
        for status in evidence.pod_statuses.values()
    )


def _normalize_job_pod_status(status: str) -> str:
    return status.strip().lower()


def _job_logs_collected_clean(result: ScanResult) -> bool:
    evidence = result.job_evidence
    if evidence is None:
        return False
    return any(excerpt.matched_pattern == "clean logs" for excerpt in evidence.log_excerpts)


def _job_running_with_clean_logs(result: ScanResult) -> bool:
    evidence = result.job_evidence
    if evidence is None:
        return False
    return (
        any(status == "Running" for status in evidence.pod_statuses.values())
        and any(excerpt.matched_pattern == "clean logs" for excerpt in evidence.log_excerpts)
        and not _has_suspicious_log_excerpts(result)
    )


def _readiness_timeout_with_clean_logs(result: ScanResult) -> bool:
    return (
        bool(_kubernetes_signal_insights(result))
        and any(
            excerpt.matched_pattern == "clean logs"
            for excerpt in _relevant_log_excerpts(result)
        )
        and not _has_suspicious_log_excerpts(result)
    )


def _has_strong_explicit_root_cause(result: ScanResult) -> bool:
    finding = result.likely_root_cause
    if finding is None:
        return False
    strong_markers = (
        "ModuleNotFoundError",
        "ImportError",
        "Traceback",
        "ImagePullBackOff",
        "ErrImagePull",
        "OOMKilled",
        "CrashLoopBackOff",
        "CreateContainerConfigError",
        "permission denied",
        "no space left on device",
        "missing Python module",
        "could not pull",
        "memory limits",
        "panic recovery events",
    )
    text = "\n".join([finding.root_cause, *finding.evidence])
    return any(marker.lower() in text.lower() for marker in strong_markers)


def _has_confirmed_root_cause(result: ScanResult) -> bool:
    if _has_strong_explicit_root_cause(result):
        return True
    return _has_strong_readiness_signal(result)


def _has_strong_readiness_signal(result: ScanResult) -> bool:
    return any(
        insight.matched_pattern.lower() == "readiness probe failed"
        and (
            "connection refused" in insight.message.lower()
            or "context deadline exceeded" in insight.message.lower()
            or "timeout" in insight.message.lower()
        )
        for insight in _kubernetes_signal_insights(result)
    )


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
        (
            "Deployment: "
            f"{metadata.get('deployment') or _successful_deployment(result) or msg.UNKNOWN_VALUE}"
        ),
        "",
        f"Namespace: {metadata.get('namespace') or msg.UNKNOWN_VALUE}",
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
        lines.append(f"- {msg.BUILD_FINISHED_SUCCESSFULLY_EVIDENCE}")

    lines.extend(["", "## Executed commands", ""])
    if evidence is not None and evidence.executed_commands:
        lines.extend(f"- `{command.command_text}`" for command in evidence.executed_commands)
    else:
        lines.append(f"- {msg.NONE_VALUE}")

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
        lines.append(f"- {msg.NONE_VALUE}")

    lines.extend(["", "## Recommended next steps", ""])
    if finding is not None:
        lines.extend(f"{index}. {item}" for index, item in enumerate(finding.what_to_check_next, 1))
    else:
        lines.append(f"1. {msg.NO_ACTION_REQUIRED}")

    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def _successful_deployment(result: ScanResult) -> str | None:
    if not result.successful_rollouts:
        return None
    return result.successful_rollouts[-1].name


def _yes_no(value: bool) -> str:
    return msg.YES if value else msg.NO


def _markdown_block(text: str) -> str:
    if not text:
        return f"- {msg.NOT_AVAILABLE}"
    return f"```text\n{text.rstrip()}\n```"


def _safe_filename(value: str) -> str:
    return "".join(
        character if character.isalnum() or character in "_.-" else "_"
        for character in value
    )
