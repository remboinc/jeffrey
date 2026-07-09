from __future__ import annotations

import re
import shlex
import time
from collections.abc import Callable
from contextlib import nullcontext
from datetime import UTC, datetime
from pathlib import Path

from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn

from jeffrey import messages as msg
from jeffrey.kubernetes import DEFAULT_KUBE_TIMEOUT, KubernetesCollector
from jeffrey.models import (
    BuildInvestigation,
    Finding,
    JenkinsJobContext,
    JenkinsRolloutContext,
    KubernetesEvidence,
    KubernetesJobEvidence,
    LogExcerpt,
    LogInsight,
    Severity,
)
from jeffrey.scanner import scan_build_log

ROLLOUT_CONTEXT_PATTERN = re.compile(
    r"(?:--namespace(?:=|\s+)|-n\s+)'?(?P<namespace>[^'\s]+)'?.*?"
    r"rollout\s+status\s+deployment\s+(?P<deployment>[^\s']+).*?"
    r"(?:--timeout(?:=|\s+)'?(?P<timeout>[^'\s]+)'?)?",
)
JOB_CONTEXT_PATTERN = re.compile(
    r"(?:--namespace(?:=|\s+)|-n\s+)'?(?P<namespace>[^'\s]+)'?.*?"
    r"\bwait\b.*?"
    r"(?:--for(?:=|\s+)'?condition=(?P<condition>[^'\s]+)'?).*?"
    r"(?:--timeout(?:=|\s+)'?(?P<timeout>[^'\s]+)'?)?.*?"
    r"(?:job\.batch/|jobs?/)(?P<job>[^'\s]+)",
)
JENKINS_TIMESTAMP_PATTERN = re.compile(r"\[(?P<timestamp>\d{4}-\d{2}-\d{2}T[^]]+Z)\]")

LOG_PATTERNS: tuple[tuple[str, Severity, int], ...] = (
    ("Traceback", Severity.CRITICAL, 1),
    ("ModuleNotFoundError", Severity.CRITICAL, 2),
    ("ImportError", Severity.CRITICAL, 3),
    ("OOMKilled", Severity.CRITICAL, 4),
    ("CrashLoopBackOff", Severity.CRITICAL, 5),
    ("ImagePullBackOff", Severity.HIGH, 6),
    ("CreateContainerConfigError", Severity.HIGH, 7),
    ("readiness probe failed", Severity.HIGH, 8),
    ("liveness probe failed", Severity.HIGH, 8),
    ("startup probe failed", Severity.HIGH, 8),
    ("connection refused", Severity.HIGH, 9),
    ("permission denied", Severity.HIGH, 10),
    ("no space left on device", Severity.HIGH, 11),
    ("Back-off", Severity.HIGH, 15),
    ("Unhealthy", Severity.HIGH, 16),
    ("Exception", Severity.HIGH, 20),
    ("CRITICAL", Severity.HIGH, 21),
    ("FATAL", Severity.HIGH, 22),
    ("Error", Severity.MEDIUM, 30),
    ("timeout", Severity.MEDIUM, 31),
    ("migration failed", Severity.HIGH, 12),
    ("django.db", Severity.HIGH, 13),
    ("pydantic", Severity.MEDIUM, 32),
    ("gunicorn", Severity.MEDIUM, 33),
    ("failed to start", Severity.HIGH, 14),
)

LOG_EXCERPT_PATTERNS: tuple[tuple[str, str, str, int], ...] = (
    ("panic recovered", "PANIC", "critical", 100),
    ("panic", "PANIC", "critical", 98),
    ("Traceback", "TRACEBACK", "critical", 98),
    ("ModuleNotFoundError", "MODULE_NOT_FOUND", "critical", 96),
    ("ImportError", "IMPORT_ERROR", "critical", 94),
    ("Exception", "EXCEPTION", "error", 90),
    ("CRITICAL", "ERROR", "error", 90),
    ("FATAL", "ERROR", "error", 90),
    ("OOMKilled", "ERROR", "critical", 88),
    ("CrashLoopBackOff", "ERROR", "critical", 86),
    ("ImagePullBackOff", "ERROR", "error", 84),
    ("CreateContainerConfigError", "ERROR", "error", 84),
    ("connection refused", "CONNECTION_REFUSED", "error", 82),
    ("permission denied", "PERMISSION_DENIED", "error", 80),
    ("no space left on device", "NO_SPACE_LEFT", "error", 80),
    ("migration failed", "MIGRATION", "error", 78),
    ("django.db", "DJANGO_DB", "error", 76),
    ("gunicorn", "GUNICORN", "warning", 72),
    ("failed to start", "ERROR", "error", 72),
    ("timeout", "TIMEOUT", "warning", 68),
    ("Error", "ERROR", "error", 60),
    ("Warning", "WARNING", "warning", 40),
)
STACK_FRAME_PATTERN = re.compile(
    r"(?:File \".+\", line \d+|^\s+at\s+|(?:[\w.-]+/)+[\w./-]+\([^)]*\)|\.go:\d+)",
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

    progress_context = (
        Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
            transient=True,
        )
        if debug
        else nullcontext(None)
    )

    with progress_context as progress:
        task_id = (
            progress.add_task("Investigating Jenkins build...", total=None)
            if progress is not None
            else None
        )
        _debug(console, debug, "Reading Jenkins log...")
        investigation = scan_build_log(path, last_lines=last_lines)
        investigation.duration_seconds = time.monotonic() - started_at
        _debug(console, debug, f"Build status: {investigation.build_status or 'UNKNOWN'}")
        if investigation.likely_root_cause and investigation.likely_root_cause.stage:
            _debug(console, debug, f"Stage: {investigation.likely_root_cause.stage}")
        _progress(console, "Jenkins log parsed", enabled=debug)

        if investigation.is_success:
            investigation.duration_seconds = time.monotonic() - started_at
            return investigation

        rollout_finding = _rollout_timeout_finding(investigation)
        job_finding = _job_timeout_finding(investigation)
        if job_finding is not None and collect_k8s:
            context = job_context_from_finding(job_finding)
            if context is not None:
                investigation.job_context = context
                job_finding.metadata.update(context.to_metadata())
                collector = collector_factory(
                    timeout=kube_timeout,
                    show_commands=show_commands,
                    debug=debug,
                    console=console,
                )
                job_evidence = collector.collect_job(context.namespace, context.job)
                job_evidence.log_excerpts = extract_log_excerpts(job_evidence)
                investigation.job_evidence = job_evidence
                _add_job_metadata(job_finding, job_evidence)
                refine_job_timeout(job_finding, context, job_evidence)
                _add_current_state_warning(investigation, job_finding)
                investigation.raw_evidence_dir = str(save_raw_evidence(None, job_evidence))
                investigation.duration_seconds = time.monotonic() - started_at
                return investigation

        if rollout_finding is None or not collect_k8s:
            investigation.duration_seconds = time.monotonic() - started_at
            return investigation

        context = rollout_context_from_finding(rollout_finding)
        if context is None:
            investigation.duration_seconds = time.monotonic() - started_at
            return investigation

        investigation.rollout_context = context
        rollout_finding.metadata.update(context.to_metadata())
        _debug(console, debug, f"Extracted namespace:\n{context.namespace}")
        _debug(console, debug, f"Extracted deployment:\n{context.deployment}")
        _progress(console, f"Deployment detected: {context.deployment}", enabled=debug)
        _progress(console, f"Namespace detected: {context.namespace}", enabled=debug)
        if context.timeout is not None:
            _progress(console, "Rollout timeout detected", enabled=debug)

        if progress is not None and task_id is not None:
            progress.update(task_id, description="Collecting deployment evidence...")
        _progress(console, "Collecting Kubernetes evidence...", enabled=debug)

        collector = collector_factory(
            timeout=kube_timeout,
            show_commands=show_commands,
            debug=debug,
            console=console,
        )
        k8s_evidence = collector.collect(context.namespace, context.deployment)
        k8s_evidence.log_insights = analyze_log_insights(k8s_evidence)
        k8s_evidence.log_excerpts = extract_log_excerpts(k8s_evidence)
        investigation.k8s_evidence = k8s_evidence
        _add_kubernetes_metadata(rollout_finding, k8s_evidence)
        _add_current_state_warning(investigation, rollout_finding)
        _progress_for_evidence(console, k8s_evidence, enabled=debug)

        if progress is not None and task_id is not None:
            progress.update(task_id, description="Correlating evidence...")
        _debug(console, debug, "Correlating evidence...")
        refine_rollout_timeout(rollout_finding, k8s_evidence)
        _debug(console, debug, "Determining root cause...")
        _debug_detected_root_cause(console, debug, rollout_finding)
        investigation.raw_evidence_dir = str(save_raw_evidence(k8s_evidence))
        _progress(console, "Investigation complete", enabled=debug)
        investigation.duration_seconds = time.monotonic() - started_at

    return investigation


def save_raw_evidence(
    evidence: KubernetesEvidence | None,
    job_evidence: KubernetesJobEvidence | None = None,
    directory: Path | None = None,
) -> Path:
    if isinstance(job_evidence, Path):
        directory = job_evidence
        job_evidence = None
    output_dir = directory or Path(".jeffrey")
    output_dir.mkdir(parents=True, exist_ok=True)

    if job_evidence is not None:
        _write_result(output_dir / "job.json", job_evidence.job_json)
        _write_result(output_dir / "job_describe.txt", job_evidence.job_description)
        _write_result(output_dir / "job_pods.json", job_evidence.job_pods_json)
        _write_result(output_dir / "job_pods.txt", job_evidence.job_pods_output)
        for pod_name, result in job_evidence.pod_descriptions.items():
            safe_name = _safe_filename(pod_name)
            _write_result(output_dir / f"job_pod_{safe_name}_describe.txt", result)
        for pod_name, result in job_evidence.pod_logs.items():
            safe_name = _safe_filename(pod_name)
            _write_result(output_dir / f"job_pod_{safe_name}_logs.txt", result)
        for pod_name, result in job_evidence.pod_previous_logs.items():
            safe_name = _safe_filename(pod_name)
            _write_result(output_dir / f"job_pod_{safe_name}_previous_logs.txt", result)
        for pod_name, result in job_evidence.pod_events.items():
            safe_name = _safe_filename(pod_name)
            _write_result(output_dir / f"job_pod_{safe_name}_events.txt", result)
        (output_dir / "commands.txt").write_text(
            "\n".join(result.command_text for result in job_evidence.executed_commands),
            encoding="utf-8",
        )
        return output_dir

    if evidence is None:
        return output_dir

    _write_result(output_dir / "deployment.json", evidence.deployment_json)
    _write_result(output_dir / "deployment_describe.txt", evidence.deployment_description)
    _write_result(output_dir / "pods.json", evidence.pods_json)
    _write_result(output_dir / "pods.txt", evidence.pods_output)
    _write_namespace_events(output_dir / "namespace_events.txt", evidence.namespace_events_output)
    _write_many(output_dir / "pod_describe.txt", evidence.pod_descriptions)
    _write_many(output_dir / "logs.txt", evidence.pod_logs)
    _write_many(output_dir / "previous_logs.txt", evidence.pod_previous_logs)
    for pod_name, result in evidence.pod_descriptions.items():
        safe_name = _safe_filename(pod_name)
        _write_result(output_dir / f"pod_{safe_name}_describe.txt", result)
    for pod_name, result in evidence.pod_events.items():
        safe_name = _safe_filename(pod_name)
        _write_result(output_dir / f"pod_{safe_name}_events.txt", result)
    for pod_name, result in evidence.pod_logs.items():
        safe_name = _safe_filename(pod_name)
        _write_result(output_dir / f"pod_{safe_name}_logs.txt", result)
    for pod_name, result in evidence.pod_previous_logs.items():
        safe_name = _safe_filename(pod_name)
        _write_result(output_dir / f"pod_{safe_name}_previous_logs.txt", result)
    (output_dir / "commands.txt").write_text(
        "\n".join(result.command_text for result in evidence.executed_commands),
        encoding="utf-8",
    )
    return output_dir


def analyze_log_insights(evidence: KubernetesEvidence) -> list[LogInsight]:
    if not evidence.selected_pods:
        return [
            LogInsight(
                pod_name=evidence.deployment,
                source="logs",
                severity=Severity.MEDIUM,
                message=msg.no_pods_matched(evidence.deployment),
                matched_pattern="no matched pods",
            )
        ]

    insights = []
    for pod_name in evidence.selected_pods:
        logs_result = evidence.pod_logs.get(pod_name)
        if logs_result is None or not logs_result.succeeded:
            insights.append(
                LogInsight(
                    pod_name=pod_name,
                    source="logs",
                    severity=Severity.MEDIUM,
                    message=msg.application_logs_unavailable(),
                    matched_pattern="logs unavailable",
                )
            )
        else:
            log_insights = _insights_from_result(pod_name, "logs", logs_result)
            if log_insights:
                insights.extend(log_insights)
            else:
                insights.append(
                    LogInsight(
                        pod_name=pod_name,
                        source="logs",
                        severity=Severity.LOW,
                        message=msg.no_startup_errors(),
                        matched_pattern="clean logs",
                    )
                )
        previous_result = evidence.pod_previous_logs.get(pod_name)
        if previous_result is not None and not previous_result.succeeded:
            insights.append(
                LogInsight(
                    pod_name=pod_name,
                    source="previous_logs",
                    severity=Severity.LOW,
                    message=msg.previous_logs_not_available(),
                    matched_pattern="previous logs unavailable",
                )
            )
        else:
            insights.extend(_insights_from_result(pod_name, "previous_logs", previous_result))

        insights.extend(
            _insights_from_result(pod_name, "describe", evidence.pod_descriptions.get(pod_name))
        )
        event_insights = _event_insights_from_result(
            pod_name,
            evidence.pod_events.get(pod_name),
        )
        if event_insights:
            insights.extend(event_insights)
        else:
            insights.append(
                LogInsight(
                    pod_name=pod_name,
                    source="events",
                    severity=Severity.LOW,
                    message=msg.no_correlated_warning_events(),
                    matched_pattern="no correlated warning events",
                )
            )

    suspicious = [
        insight
        for insight in insights
        if insight.matched_pattern
        not in {
            "previous logs unavailable",
            "no correlated warning events",
            "logs unavailable",
        }
    ]
    if not suspicious:
        unavailable_log_insights = [
            insight for insight in insights if insight.matched_pattern == "logs unavailable"
        ]
        if unavailable_log_insights:
            return unavailable_log_insights + [
                insight
                for insight in insights
                if insight.matched_pattern
                in {"previous logs unavailable", "no correlated warning events"}
            ]
        return [
            insight
            for insight in insights
            if insight.matched_pattern
            in {
                "clean logs",
                "previous logs unavailable",
                "no correlated warning events",
                "logs unavailable",
            }
        ]

    return sorted(insights, key=_log_insight_rank)


def extract_log_excerpts(evidence: KubernetesEvidence) -> list[LogExcerpt]:
    if not evidence.selected_pods:
        workload_name = getattr(evidence, "deployment", getattr(evidence, "job", "workload"))
        return [
            LogExcerpt(
                pod_name=workload_name,
                source="logs",
                severity="info",
                label="UNKNOWN",
                message=msg.no_pods_matched(workload_name),
                matched_pattern="no matched pods",
                score=0,
            )
        ]

    excerpts: list[LogExcerpt] = []
    for pod_name in evidence.selected_pods:
        for source, result in (
            ("logs", evidence.pod_logs.get(pod_name)),
            ("previous_logs", evidence.pod_previous_logs.get(pod_name)),
        ):
            if result is None or not result.succeeded:
                excerpts.append(
                    LogExcerpt(
                        pod_name=pod_name,
                        source=source,
                        severity="info",
                        label="UNKNOWN",
                        message=msg.log_unavailable(source, pod_name),
                        matched_pattern=f"{source} unavailable",
                        score=0,
                    )
                )
                continue

            source_excerpts = _extract_excerpts_from_text(
                pod_name,
                source,
                "\n".join(part for part in (result.stdout, result.stderr) if part),
            )
            if source_excerpts:
                excerpts.extend(source_excerpts)
            elif source == "logs":
                excerpts.append(
                    LogExcerpt(
                        pod_name=pod_name,
                        source=source,
                        severity="info",
                        label="UNKNOWN",
                        message=msg.no_suspicious_log_lines(pod_name),
                        matched_pattern="clean logs",
                        score=0,
                    )
                )

    return _deduplicate_excerpts(excerpts)


def _extract_excerpts_from_text(
    pod_name: str,
    source: str,
    text: str,
) -> list[LogExcerpt]:
    excerpts = []
    lines = text.splitlines()
    for index, line in enumerate(lines):
        excerpt = _excerpt_from_line(pod_name, source, line, index + 1)
        if excerpt is not None:
            excerpts.append(excerpt)
        if excerpt is not None and excerpt.score >= 90:
            excerpts.extend(_supporting_excerpts(pod_name, source, lines, index))
    return sorted(excerpts, key=_excerpt_sort_key)


def _supporting_excerpts(
    pod_name: str,
    source: str,
    lines: list[str],
    index: int,
) -> list[LogExcerpt]:
    excerpts = []
    for neighbor_index in (index - 1, index + 1):
        if neighbor_index < 0 or neighbor_index >= len(lines):
            continue
        line = lines[neighbor_index]
        if not _is_supporting_log_line(line):
            continue
        excerpt = _excerpt_from_line(pod_name, source, line, neighbor_index + 1)
        if excerpt is not None:
            excerpts.append(excerpt)
    return excerpts


def _is_supporting_log_line(line: str) -> bool:
    stripped = line.strip()
    if not stripped:
        return False
    lower_line = stripped.lower()
    return (
        "panic" in lower_line
        or "recovery" in lower_line
        or "error" in lower_line
        or _is_stack_frame_line(stripped)
    )


def _excerpt_from_line(
    pod_name: str,
    source: str,
    line: str,
    line_number: int,
) -> LogExcerpt | None:
    stripped = line.strip()
    if not stripped:
        return None

    pattern = _match_log_excerpt_pattern(stripped)
    if _is_stack_frame_line(stripped) and (
        pattern is None or pattern[1] in {"ERROR", "WARNING"}
    ):
        pattern = ("stack frame", "STACK", "info", 25)
    if pattern is None:
        return None

    matched_pattern, label, severity, score = pattern
    return LogExcerpt(
        pod_name=pod_name,
        source=source,
        severity=severity,
        label=label,
        message=_trim_log_message(stripped),
        matched_pattern=matched_pattern,
        score=score,
        line_number=line_number,
    )


def _match_log_excerpt_pattern(line: str) -> tuple[str, str, str, int] | None:
    lower_line = line.lower()
    for pattern, label, severity, score in LOG_EXCERPT_PATTERNS:
        if pattern.lower() in lower_line:
            return pattern, label, severity, score
    return None


def _is_stack_frame_line(line: str) -> bool:
    return STACK_FRAME_PATTERN.search(line) is not None


def _deduplicate_excerpts(excerpts: list[LogExcerpt]) -> list[LogExcerpt]:
    deduped = []
    seen = set()
    for excerpt in sorted(excerpts, key=_excerpt_sort_key):
        key = _excerpt_dedup_key(excerpt)
        if key in seen:
            continue
        seen.add(key)
        deduped.append(excerpt)
    return deduped


def _excerpt_dedup_key(excerpt: LogExcerpt) -> tuple[str, str, str]:
    normalized = re.sub(r"\d+", "0", excerpt.message.lower())
    normalized = re.sub(r"\s+", " ", normalized).strip()
    if excerpt.label == "STACK":
        normalized = normalized.split("(", 1)[0]
    return (excerpt.pod_name, excerpt.label, normalized)


def _excerpt_sort_key(excerpt: LogExcerpt) -> tuple[int, int]:
    source_rank = 0 if excerpt.source == "previous_logs" else 1
    return (-excerpt.score, source_rank)


def _trim_log_message(message: str, limit: int = 180) -> str:
    if len(message) <= limit:
        return message
    return message[: limit - 3].rstrip() + "..."


def rollout_context_from_finding(finding: Finding) -> JenkinsRolloutContext | None:
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


def job_context_from_finding(finding: Finding) -> JenkinsJobContext | None:
    for evidence in finding.evidence:
        if evidence.startswith("Jenkins job command: "):
            command = evidence.removeprefix("Jenkins job command: ")
        elif evidence.startswith("Command: "):
            command = evidence.removeprefix("Command: ")
        else:
            continue

        context = parse_job_wait_command(command)
        if context is not None:
            return context
    return None


def parse_rollout_command(command: str) -> JenkinsRolloutContext | None:
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

    return JenkinsRolloutContext(
        namespace=namespace,
        deployment=deployment,
        timeout=timeout,
        command=command,
    )


def parse_job_wait_command(command: str) -> JenkinsJobContext | None:
    try:
        tokens = shlex.split(command)
    except ValueError:
        return _parse_job_wait_command_with_regex(command)

    namespace = None
    job = None
    timeout = None
    condition = None

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
        elif token.startswith("--for=condition="):
            condition = token.split("=", 2)[2]
        elif token == "--for" and index + 1 < len(tokens):
            value = tokens[index + 1]
            if value.startswith("condition="):
                condition = value.split("=", 1)[1]
        elif token.startswith("job.batch/"):
            job = token.split("/", 1)[1]
        elif token.startswith("jobs/"):
            job = token.split("/", 1)[1]

    if namespace is None or job is None:
        return _parse_job_wait_command_with_regex(command)
    return JenkinsJobContext(
        namespace=namespace,
        job=job,
        timeout=timeout,
        condition=condition,
        command=command,
    )


def refine_rollout_timeout(finding: Finding, evidence: KubernetesEvidence) -> None:
    if _refine_from_log_excerpts(finding, evidence):
        return
    if _refine_from_log_insights(finding, evidence.log_insights):
        return

    combined = "\n".join(_correlated_kubernetes_text_blocks(evidence))
    lower_combined = combined.lower()

    refinements = (
        (
            "CrashLoopBackOff",
            msg.ROOT_CAUSE_CRASH_LOOP,
            msg.NEXT_STEPS_STARTUP,
        ),
        (
            "ImagePullBackOff",
            msg.ROOT_CAUSE_IMAGE_PULL,
            msg.NEXT_STEPS_IMAGE_PULL,
        ),
        (
            "ErrImagePull",
            msg.ROOT_CAUSE_IMAGE_PULL,
            msg.NEXT_STEPS_IMAGE_PULL,
        ),
        (
            "OOMKilled",
            msg.ROOT_CAUSE_OOM_KILLED,
            msg.NEXT_STEPS_MEMORY,
        ),
        (
            "CreateContainerConfigError",
            msg.ROOT_CAUSE_CONTAINER_CONFIG,
            msg.NEXT_STEPS_CONTAINER_CONFIG,
        ),
        (
            "Readiness probe failed",
            msg.ROOT_CAUSE_READINESS_FAILED,
            msg.NEXT_STEPS_READINESS,
        ),
        (
            "connection refused",
            msg.ROOT_CAUSE_DEPENDENCY_CONNECTION_REFUSED,
            msg.NEXT_STEPS_CONNECTION,
        ),
        (
            "ModuleNotFoundError",
            msg.ROOT_CAUSE_MISSING_PYTHON_MODULE,
            msg.NEXT_STEPS_PYTHON_IMPORT,
        ),
        (
            "permission denied",
            msg.ROOT_CAUSE_PERMISSION_ERROR,
            msg.NEXT_STEPS_PERMISSION,
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


def refine_job_timeout(
    finding: Finding,
    context: JenkinsJobContext,
    evidence: KubernetesJobEvidence,
) -> None:
    original_evidence = list(finding.evidence)
    finding.root_cause = f"Kubernetes Job {context.job} timed out before completion."
    finding.evidence = [
        msg.jenkins_job_timed_out(context.job, context.condition, context.timeout),
    ]
    for line in _job_error_lines(original_evidence):
        finding.evidence.append(msg.jenkins_job_error(line))
    for pod_name in evidence.selected_pods[:1]:
        finding.evidence.append(
            msg.job_pod_status(pod_name, evidence.pod_statuses.get(pod_name, "Unknown"))
        )
    important_excerpt = next(
        (excerpt for excerpt in evidence.log_excerpts if excerpt.score > 0),
        None,
    )
    if important_excerpt is not None:
        finding.evidence.append(msg.job_pod_logs_contain(important_excerpt.message))
    elif not evidence.selected_pods:
        finding.evidence.append(msg.job_pod_logs_not_analyzed(context.job))
    finding.evidence = list(dict.fromkeys(finding.evidence))


def _job_error_lines(evidence_lines: list[str]) -> list[str]:
    return [
        line
        for line in evidence_lines
        if "timed out waiting for the condition" in line and not line.startswith("Jenkins")
    ]


def _refine_from_log_excerpts(finding: Finding, evidence: KubernetesEvidence) -> bool:
    actionable = [
        excerpt
        for excerpt in evidence.log_excerpts
        if excerpt.score > 0 and excerpt.label not in {"STACK", "WARNING"}
    ]
    if not actionable:
        return False

    top_labels = {excerpt.label for excerpt in actionable[:3]}
    has_readiness = any(
        insight.matched_pattern.lower() == "readiness probe failed"
        for insight in evidence.log_insights
    )

    if "PANIC" in top_labels:
        _add_log_excerpt_evidence(finding, actionable[0])
        if has_readiness:
            finding.root_cause = msg.ROOT_CAUSE_PANIC_WITH_READINESS
        else:
            finding.root_cause = msg.ROOT_CAUSE_PANIC
        return True
    if "MODULE_NOT_FOUND" in top_labels:
        _add_log_excerpt_evidence(finding, actionable[0])
        finding.root_cause = msg.ROOT_CAUSE_MISSING_PYTHON_MODULE
        return True
    if "IMPORT_ERROR" in top_labels:
        _add_log_excerpt_evidence(finding, actionable[0])
        finding.root_cause = msg.ROOT_CAUSE_IMPORT_ERROR
        return True
    if "CONNECTION_REFUSED" in top_labels:
        _add_log_excerpt_evidence(finding, actionable[0])
        finding.root_cause = msg.ROOT_CAUSE_APP_LOGS_CONNECTION_REFUSED
        return True
    return False


def _add_kubernetes_metadata(finding: Finding, evidence: KubernetesEvidence) -> None:
    finding.metadata.update(
        {
            "has_k8s_evidence": "true",
            "namespace": evidence.namespace,
            "deployment": evidence.deployment,
            "selector": evidence.selector_text or "unavailable",
            "fallback_pod_matching_used": str(evidence.fallback_pod_matching_used).lower(),
            "deployment_description": _availability(evidence.deployment_description),
            "pods_checked": str(evidence.pods_checked),
            "events_checked": _availability(evidence.namespace_events_output),
            "previous_logs_checked": _previous_logs_availability(evidence),
            "executed_commands": str(len(evidence.executed_commands)),
            "correlated_events_found": str(evidence.correlated_events_found),
            "unrelated_namespace_events_ignored": str(
                evidence.unrelated_namespace_events_ignored
            ),
            "first_pod": evidence.selected_pods[0] if evidence.selected_pods else "",
        }
    )


def _add_job_metadata(finding: Finding, evidence: KubernetesJobEvidence) -> None:
    finding.metadata.update(
        {
            "has_job_evidence": "true",
            "namespace": evidence.namespace,
            "job": evidence.job,
            "selector": evidence.selector_text or "unavailable",
            "pods_checked": str(evidence.pods_checked),
            "previous_logs_checked": _previous_logs_availability(evidence),
            "executed_commands": str(len(evidence.executed_commands)),
            "first_pod": evidence.selected_pods[0] if evidence.selected_pods else "",
        }
    )


def _add_current_state_warning(
    investigation: BuildInvestigation,
    finding: Finding,
) -> None:
    failed_at = _jenkins_failure_timestamp(finding)
    if failed_at is None:
        return
    age = datetime.now(UTC) - failed_at
    if age.total_seconds() > 600:
        if investigation.job_context is not None:
            investigation.warnings.append(
                msg.current_job_state_warning(failed_at.isoformat().replace("+00:00", "Z"))
            )
            return
        investigation.warnings.append(
            msg.current_state_warning(failed_at.isoformat().replace("+00:00", "Z"))
        )


def _insights_from_result(
    pod_name: str,
    source: str,
    result: object | None,
) -> list[LogInsight]:
    if result is None:
        return []
    text = "\n".join(
        part
        for part in (getattr(result, "stdout", ""), getattr(result, "stderr", ""))
        if part
    )
    insights = []
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        if source == "describe" and _is_probe_configuration_line(stripped):
            continue
        match = _match_log_pattern(stripped)
        if match is None:
            continue
        pattern, severity, _rank = match
        insights.append(
            LogInsight(
                pod_name=pod_name,
                source=source,
                severity=severity,
                message=stripped,
                matched_pattern=pattern,
            )
        )
    return insights


def _is_probe_configuration_line(line: str) -> bool:
    return line.startswith(("Liveness:", "Readiness:", "Startup:"))


def _event_insights_from_result(
    pod_name: str,
    result: object | None,
) -> list[LogInsight]:
    insights = []
    for line in _pod_specific_event_lines(pod_name, result):
        match = _match_log_pattern(line)
        if match is None:
            continue
        pattern, severity, _rank = match
        insights.append(
            LogInsight(
                pod_name=pod_name,
                source="events",
                severity=severity,
                message=line.strip(),
                matched_pattern=pattern,
            )
        )
    return insights


def _match_log_pattern(line: str) -> tuple[str, Severity, int] | None:
    lower_line = line.lower()
    for pattern, severity, rank in LOG_PATTERNS:
        if pattern.lower() in lower_line:
            return pattern, severity, rank
    return None


def _log_insight_rank(insight: LogInsight) -> tuple[int, int]:
    for pattern, _severity, rank in LOG_PATTERNS:
        if insight.matched_pattern.lower() == pattern.lower():
            return (rank, _source_rank(insight.source))
    low_priority = {
        "clean logs": 89,
        "previous logs unavailable": 90,
        "no correlated warning events": 91,
        "logs unavailable": 91,
        "no matched pods": 93,
    }
    return (low_priority.get(insight.matched_pattern, 99), _source_rank(insight.source))


def _source_rank(source: str) -> int:
    ranks = {
        "previous_logs": 0,
        "logs": 1,
        "describe": 2,
        "events": 3,
    }
    return ranks.get(source, 9)


def _refine_from_log_insights(finding: Finding, insights: list[LogInsight]) -> bool:
    readiness_insights = [
        insight
        for insight in insights
        if insight.matched_pattern.lower() == "readiness probe failed"
    ]
    if readiness_insights:
        messages = "\n".join(insight.message.lower() for insight in readiness_insights)
        refused = "connection refused" in messages or "refused" in messages
        timed_out = "context deadline exceeded" in messages or "timeout" in messages
        for insight in readiness_insights[:2]:
            _add_log_insight_evidence(finding, insight)
        if refused and timed_out:
            finding.root_cause = msg.ROOT_CAUSE_READINESS_UNRELIABLE
            return True
        if refused:
            finding.root_cause = msg.ROOT_CAUSE_READINESS_PORT_REFUSED
            return True
        if timed_out:
            finding.root_cause = msg.ROOT_CAUSE_READINESS_TIMED_OUT
            return True

    for insight in sorted(insights, key=_log_insight_rank):
        pattern = insight.matched_pattern.lower()
        if pattern == "modulenotfounderror":
            _add_log_insight_evidence(finding, insight)
            finding.root_cause = msg.ROOT_CAUSE_MISSING_PYTHON_MODULE
            finding.what_to_check_next = list(msg.NEXT_STEPS_PYTHON_IMPORT)
            return True
        if pattern == "connection refused":
            _add_log_insight_evidence(finding, insight)
            finding.root_cause = msg.ROOT_CAUSE_APP_LOGS_CONNECTION_REFUSED
            finding.what_to_check_next = list(msg.NEXT_STEPS_CONNECTION)
            return True
        if pattern == "readiness probe failed":
            _add_log_insight_evidence(finding, insight)
            finding.root_cause = msg.ROOT_CAUSE_READINESS_FAILED
            finding.what_to_check_next = list(msg.NEXT_STEPS_READINESS)
            return True
    return False


def _add_log_insight_evidence(finding: Finding, insight: LogInsight) -> None:
    source = insight.source.replace("_", " ")
    line = f"pod/{insight.pod_name} {source}: {insight.message}"
    if line not in finding.evidence:
        finding.evidence.append(line)


def _add_log_excerpt_evidence(finding: Finding, excerpt: LogExcerpt) -> None:
    source = excerpt.source.replace("_", " ")
    line = f"pod/{excerpt.pod_name} {source}: {excerpt.message}"
    if line not in finding.evidence:
        finding.evidence.append(line)


def _jenkins_failure_timestamp(finding: Finding) -> datetime | None:
    for evidence in reversed(finding.evidence):
        match = JENKINS_TIMESTAMP_PATTERN.search(evidence)
        if match is None:
            continue
        raw_timestamp = match.group("timestamp")
        try:
            return datetime.fromisoformat(raw_timestamp.replace("Z", "+00:00"))
        except ValueError:
            return None
    return None


def _rollout_timeout_finding(investigation: BuildInvestigation) -> Finding | None:
    for finding in investigation.findings:
        if finding.title == "Deployment rollout timed out":
            return finding
    return None


def _job_timeout_finding(investigation: BuildInvestigation) -> Finding | None:
    for finding in investigation.findings:
        if finding.title == "Kubernetes Job timed out":
            return finding
    return None


def _parse_rollout_command_with_regex(command: str) -> JenkinsRolloutContext | None:
    match = ROLLOUT_CONTEXT_PATTERN.search(command)
    if match is None:
        return None

    return JenkinsRolloutContext(
        namespace=match.group("namespace"),
        deployment=match.group("deployment"),
        timeout=match.group("timeout"),
        command=command,
    )


def _parse_job_wait_command_with_regex(command: str) -> JenkinsJobContext | None:
    match = JOB_CONTEXT_PATTERN.search(command)
    if match is None:
        return None
    return JenkinsJobContext(
        namespace=match.group("namespace"),
        job=match.group("job"),
        timeout=match.group("timeout"),
        condition=match.group("condition"),
        command=command,
    )


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


def _correlated_kubernetes_text_blocks(evidence: KubernetesEvidence) -> list[str]:
    blocks = []
    if evidence.deployment_description is not None:
        blocks.extend(
            [
                evidence.deployment_description.stdout,
                evidence.deployment_description.stderr,
            ]
        )
    if evidence.pods_output is not None:
        blocks.extend(_related_pod_lines(evidence))
    if evidence.events_output is not None:
        blocks.extend(_related_event_lines(evidence))
    for pod_name, result in evidence.pod_events.items():
        blocks.extend(_pod_specific_event_lines(pod_name, result))
        blocks.append(result.stderr)
    for result in (
        *evidence.pod_descriptions.values(),
        *evidence.pod_logs.values(),
        *evidence.pod_previous_logs.values(),
    ):
        blocks.extend([result.stdout, result.stderr])
    return blocks


def _important_evidence_lines(evidence: KubernetesEvidence, needle: str) -> list[str]:
    lines = []
    for label, text in _labeled_correlated_kubernetes_text(evidence):
        for line in text.splitlines():
            if needle.lower() in line.lower():
                lines.append(f"{label}: {line.strip()}")
                if len(lines) >= 3:
                    return lines
    return lines


def _related_pod_lines(evidence: KubernetesEvidence) -> list[str]:
    if evidence.pods_output is None:
        return []

    selected_pods = set(evidence.selected_pods)
    lines = []
    for line in evidence.pods_output.stdout.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        if stripped.lower().startswith("name "):
            lines.append(stripped)
            continue
        pod_name = stripped.split()[0]
        if pod_name in selected_pods:
            lines.append(stripped)
    return lines


def _related_event_lines(evidence: KubernetesEvidence) -> list[str]:
    if evidence.namespace_events_output is None:
        return []

    lines = []
    selected_pods = set(evidence.selected_pods)
    deployment_markers = {
        f"deployment/{evidence.deployment}",
        f'deployment "{evidence.deployment}"',
        f"deployment.apps/{evidence.deployment}",
    }

    for line in evidence.namespace_events_output.stdout.splitlines():
        if _line_mentions_selected_pod(line, selected_pods) or any(
            marker in line for marker in deployment_markers
        ) or any(replica_set in line for replica_set in evidence.replica_sets):
            lines.append(line)
    return lines


def _pod_specific_event_lines(pod_name: str, result: object | None) -> list[str]:
    if result is None:
        return []
    stdout = getattr(result, "stdout", "")
    return [
        line
        for line in stdout.splitlines()
        if line.strip() and (f"pod/{pod_name}" in line or pod_name in line)
    ]


def _line_mentions_selected_pod(line: str, selected_pods: set[str]) -> bool:
    return any(f"pod/{pod_name}" in line or pod_name in line for pod_name in selected_pods)


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
        lines.append(f"Kubernetes namespace events output: {status}")
    if evidence.selected_pods:
        lines.append(
            "Kubernetes evidence was collected, but no correlated pod/deployment "
            "failure was found."
        )
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


def _labeled_correlated_kubernetes_text(evidence: KubernetesEvidence) -> list[tuple[str, str]]:
    labeled = []
    if evidence.deployment_description is not None:
        labeled.append(("Kubernetes", evidence.deployment_description.stdout))
        labeled.append(("Kubernetes", evidence.deployment_description.stderr))
    if evidence.pods_output is not None:
        labeled.append(("Kubernetes", "\n".join(_related_pod_lines(evidence))))
        labeled.append(("Kubernetes", evidence.pods_output.stderr))
    if evidence.events_output is not None:
        labeled.append(("Kubernetes", "\n".join(_related_event_lines(evidence))))
        labeled.append(("Kubernetes", evidence.events_output.stderr))
    for pod_name, result in evidence.pod_events.items():
        pod_event_lines = "\n".join(_pod_specific_event_lines(pod_name, result))
        labeled.append(
            (f"Kubernetes pod events {pod_name}", pod_event_lines)
        )
        labeled.append((f"Kubernetes pod events {pod_name}", result.stderr))
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


def _progress_for_evidence(
    console: Console,
    evidence: KubernetesEvidence,
    *,
    enabled: bool,
) -> None:
    _progress(console, "Deployment described", enabled=enabled)
    _progress(console, "Pods collected", enabled=enabled)
    _progress(console, "Events collected", enabled=enabled)
    if evidence.pod_logs or evidence.pod_previous_logs:
        _progress(console, "Pod logs collected", enabled=enabled)


def _progress(console: Console, message: str, *, enabled: bool) -> None:
    if enabled:
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


def _write_namespace_events(path: Path, result: object | None) -> None:
    header = (
        "Uncorrelated raw namespace event context. These events are saved for manual "
        "debugging and are not used as primary report evidence unless they mention "
        "the investigated deployment, selected pods, or selected ReplicaSets.\n\n"
    )
    if result is None:
        path.write_text(header, encoding="utf-8")
        return
    stdout = getattr(result, "stdout", "")
    stderr = getattr(result, "stderr", "")
    path.write_text(header + _join_output(stdout, stderr), encoding="utf-8")


def _safe_filename(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]+", "_", value)
