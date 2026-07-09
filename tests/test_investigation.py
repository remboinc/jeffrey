from __future__ import annotations

import subprocess
from io import StringIO
from pathlib import Path

from rich.console import Console

from jeffrey.investigation import (
    analyze_log_insights,
    extract_log_excerpts,
    investigate_build_log,
    parse_job_wait_command,
    parse_rollout_command,
    save_raw_evidence,
)
from jeffrey.models import CommandResult, KubernetesEvidence
from jeffrey.reporter import print_report, save_markdown_report

ROLLOUT_COMMAND = "kubectl '--namespace=demo' rollout status deployment web-app '--timeout=150s'"
JOB_COMMAND = (
    "kubectl '--namespace=demo' wait '--for=condition=complete' "
    "'--timeout=1200s' job.batch/data-job"
)


def test_namespace_is_extracted_from_rollout_command() -> None:
    assert parse_rollout_command(ROLLOUT_COMMAND)["namespace"] == "demo"


def test_deployment_is_extracted_from_rollout_command() -> None:
    assert parse_rollout_command(ROLLOUT_COMMAND)["deployment"] == "web-app"


def test_timeout_is_extracted_from_rollout_command() -> None:
    assert parse_rollout_command(ROLLOUT_COMMAND)["timeout"] == "150s"


def test_namespace_is_extracted_from_job_wait_command() -> None:
    assert parse_job_wait_command(JOB_COMMAND)["namespace"] == "demo"


def test_job_name_is_extracted_from_job_wait_command() -> None:
    assert parse_job_wait_command(JOB_COMMAND)["job"] == "data-job"


def test_timeout_is_extracted_from_job_wait_command() -> None:
    assert parse_job_wait_command(JOB_COMMAND)["timeout"] == "1200s"


def test_kubectl_wait_job_timeout_is_investigated(tmp_path: Path, monkeypatch) -> None:
    log_path = _write_failed_job_log(tmp_path)
    monkeypatch.chdir(tmp_path)
    commands = []

    def fake_run(command, **kwargs):
        commands.append(command)
        return _completed_job(command)

    monkeypatch.setattr(subprocess, "run", fake_run)

    result = investigate_build_log(log_path)
    output = StringIO()
    console = Console(file=output, force_terminal=False)
    print_report(result, console=console)

    rendered = output.getvalue()
    assert result.job_evidence is not None
    assert result.k8s_evidence is None
    assert result.likely_root_cause.root_cause == (
        "Kubernetes Job data-job timed out before completion."
    )
    assert "Deployment rollout timed out" not in result.likely_root_cause.root_cause
    assert "Job:" in rendered
    assert "data-job" in rendered
    assert ["kubectl", "describe", "job", "data-job", "-n", "demo"] in commands


def test_job_selector_is_used_to_find_pods(tmp_path: Path, monkeypatch) -> None:
    log_path = _write_failed_job_log(tmp_path)
    monkeypatch.chdir(tmp_path)
    commands = []

    def fake_run(command, **kwargs):
        commands.append(command)
        return _completed_job(command)

    monkeypatch.setattr(subprocess, "run", fake_run)

    investigate_build_log(log_path)

    assert [
        "kubectl",
        "get",
        "pods",
        "-n",
        "demo",
        "-l",
        "controller-uid=job-uid",
        "-o",
        "json",
    ] in commands


def test_job_name_fallback_label_is_used_if_selector_missing(tmp_path: Path, monkeypatch) -> None:
    log_path = _write_failed_job_log(tmp_path)
    monkeypatch.chdir(tmp_path)
    commands = []

    def fake_run(command, **kwargs):
        commands.append(command)
        return _completed_job(command, selector=False)

    monkeypatch.setattr(subprocess, "run", fake_run)

    result = investigate_build_log(log_path)

    assert result.job_evidence is not None
    assert result.job_evidence.fallback_label_used == "job-name=data-job"
    assert [
        "kubectl",
        "get",
        "pods",
        "-n",
        "demo",
        "-l",
        "job-name=data-job",
        "-o",
        "json",
    ] in commands


def test_job_pod_logs_and_previous_logs_are_collected(tmp_path: Path, monkeypatch) -> None:
    log_path = _write_failed_job_log(tmp_path)
    monkeypatch.chdir(tmp_path)
    commands = []

    def fake_run(command, **kwargs):
        commands.append(command)
        return _completed_job(command, logs="Error: migration failed\n")

    monkeypatch.setattr(subprocess, "run", fake_run)

    result = investigate_build_log(log_path)

    assert result.job_evidence is not None
    assert "data-job-abc" in result.job_evidence.pod_logs
    assert "data-job-abc" in result.job_evidence.pod_previous_logs
    assert ["kubectl", "logs", "data-job-abc", "-n", "demo", "--tail=200"] in commands
    assert [
        "kubectl",
        "logs",
        "data-job-abc",
        "-n",
        "demo",
        "--previous",
        "--tail=200",
    ] in commands


def test_job_relevant_log_excerpts_are_shown(tmp_path: Path, monkeypatch) -> None:
    log_path = _write_failed_job_log(tmp_path)
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(
        subprocess,
        "run",
        lambda command, **kwargs: _completed_job(command, logs="Error: migration failed\n"),
    )

    result = investigate_build_log(log_path)
    output = StringIO()
    console = Console(file=output, force_terminal=False)
    print_report(result, console=console)

    rendered = output.getvalue()
    assert "Relevant log excerpts:" in rendered
    assert "[MIGRATION] pod/data-job-abc logs: Error: migration failed" in rendered


def test_job_report_omits_unrelated_namespace_events(tmp_path: Path, monkeypatch) -> None:
    log_path = _write_failed_job_log(tmp_path)
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(subprocess, "run", _completed_job)

    result = investigate_build_log(log_path)
    output = StringIO()
    console = Console(file=output, force_terminal=False)
    print_report(result, console=console)

    assert "other-api" not in output.getvalue()


def test_job_default_evidence_omits_generic_collected_available_lines(
    tmp_path: Path,
    monkeypatch,
) -> None:
    log_path = _write_failed_job_log(tmp_path)
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(subprocess, "run", _completed_job)

    result = investigate_build_log(log_path)
    output = StringIO()
    console = Console(file=output, force_terminal=False)
    print_report(result, console=console)

    evidence = _section(output.getvalue(), "Evidence:", "Kubernetes signal:")
    assert "collected" not in evidence
    assert "available" not in evidence
    assert "namespace events" not in evidence


def test_old_job_timestamp_prints_job_state_warning(tmp_path: Path, monkeypatch) -> None:
    log_path = _write_failed_job_log(tmp_path, timestamp="2020-01-01T00:00:00.000Z")
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(subprocess, "run", _completed_job)

    result = investigate_build_log(log_path)
    output = StringIO()
    console = Console(file=output, force_terminal=False)
    print_report(result, console=console)

    rendered = output.getvalue()
    assert "Current Job/Pod state may differ" in rendered
    assert "2020-01-01T00:00:00Z" in rendered


def test_no_job_pods_reports_logs_not_analyzed(tmp_path: Path, monkeypatch) -> None:
    log_path = _write_failed_job_log(tmp_path)
    monkeypatch.chdir(tmp_path)

    def fake_run(command, **kwargs):
        if command[:4] == ["kubectl", "get", "pods", "-n"] and "-o" in command:
            return subprocess.CompletedProcess(command, 0, stdout='{"items":[]}', stderr="")
        return _completed_job(command)

    monkeypatch.setattr(subprocess, "run", fake_run)

    result = investigate_build_log(log_path)
    output = StringIO()
    console = Console(file=output, force_terminal=False)
    print_report(result, console=console)

    assert "Job pod logs could not be analyzed" in output.getvalue()


def test_job_raw_evidence_files_are_saved(tmp_path: Path, monkeypatch) -> None:
    log_path = _write_failed_job_log(tmp_path)
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(subprocess, "run", _completed_job)

    investigate_build_log(log_path)

    evidence_dir = tmp_path / ".jeffrey"
    assert (evidence_dir / "job.json").exists()
    assert (evidence_dir / "job_describe.txt").exists()
    assert (evidence_dir / "job_pods.json").exists()
    assert (evidence_dir / "job_pods.txt").exists()
    assert (evidence_dir / "job_pod_data-job-abc_describe.txt").exists()
    assert (evidence_dir / "job_pod_data-job-abc_logs.txt").exists()
    assert (evidence_dir / "job_pod_data-job-abc_previous_logs.txt").exists()
    assert (evidence_dir / "job_pod_data-job-abc_events.txt").exists()


def test_redis_sentinel_discovered_new_sentinel_is_not_stack() -> None:
    evidence = _evidence_with_logs(
        "sentinel.go:700: sentinel: discovered new sentinel at 10.0.0.1:26379\n"
    )

    excerpts = extract_log_excerpts(evidence)

    assert all(excerpt.label != "STACK" for excerpt in excerpts)
    assert excerpts[0].matched_pattern == "clean logs"


def test_go_file_reference_alone_is_not_stack() -> None:
    evidence = _evidence_with_logs("worker.go:42: processing item\n")

    excerpts = extract_log_excerpts(evidence)

    assert all(excerpt.label != "STACK" for excerpt in excerpts)
    assert excerpts[0].matched_pattern == "clean logs"


def test_job_info_logs_have_no_suspicious_patterns(tmp_path: Path, monkeypatch) -> None:
    log_path = _write_failed_job_log(tmp_path)
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(
        subprocess,
        "run",
        lambda command, **kwargs: _completed_job(
            command,
            logs="sentinel.go:700: sentinel: discovered new sentinel\n",
        ),
    )

    result = investigate_build_log(log_path)
    output = StringIO()
    console = Console(file=output, force_terminal=False)
    print_report(result, console=console)

    rendered = output.getvalue()
    assert "[STACK]" not in rendered
    assert "Job pod logs were collected" in rendered
    assert "no suspicious error patterns were detected" in _normalized_output(output)


def test_no_contradictory_job_conclusion_when_logs_collected(
    tmp_path: Path,
    monkeypatch,
) -> None:
    log_path = _write_failed_job_log(tmp_path)
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(subprocess, "run", _completed_job)

    result = investigate_build_log(log_path)
    output = StringIO()
    console = Console(file=output, force_terminal=False)
    print_report(result, console=console)

    rendered = output.getvalue()
    conclusion = _section(rendered, "Jeffrey conclusion:", "Warning:")
    assert "Jeffrey found the Job pod and analyzed its logs." not in conclusion
    assert "Application logs could not be collected." not in rendered
    assert "Job pod logs could not be collected." not in rendered
    assert "Job pod logs were collected" not in conclusion
    assert "Previous logs were not available" not in conclusion


def test_running_job_clean_logs_conclusion_has_possible_explanations(
    tmp_path: Path,
    monkeypatch,
) -> None:
    log_path = _write_failed_job_log(tmp_path)
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(
        subprocess,
        "run",
        lambda command, **kwargs: _completed_job(command, pod_status="Running"),
    )

    result = investigate_build_log(log_path)
    output = StringIO()
    console = Console(file=output, force_terminal=False)
    print_report(result, console=console)

    rendered = _normalized_output(output)
    conclusion = _section(rendered, "Jeffrey conclusion:", "Possible explanations:")
    assert "Jenkins waited 1200s for the Kubernetes Job to complete." in conclusion
    assert "The Job pod is still Running." in conclusion
    assert (
        "The Job did not fail; it simply did not finish within the configured timeout."
        in conclusion
    )
    assert "Most likely, the Job command is still executing" in conclusion
    assert "Job pod logs were collected" not in conclusion
    assert "Previous logs were not available" not in conclusion
    assert "Possible explanations:" in rendered
    assert "Long-running migration or maintenance command" in rendered
    assert "Timeout value is too small for this operation" in rendered


def test_job_timeout_completed_current_pod_produces_state_changed_conclusion(
    tmp_path: Path,
    monkeypatch,
) -> None:
    log_path = _write_failed_job_log(tmp_path, timestamp="2026-07-09T18:32:42Z")
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(
        subprocess,
        "run",
        lambda command, **kwargs: _completed_job(command, pod_status="Completed"),
    )

    result = investigate_build_log(log_path)
    output = StringIO()
    console = Console(file=output, force_terminal=False)
    print_report(result, console=console)

    rendered = _normalized_output(output)
    assert "Kubernetes Job data-job timed out before completion." in rendered
    assert "Jenkins observed the Job as incomplete during the build." in rendered
    assert "Current Job pod status is Completed." in rendered
    assert "Current Job/Pod state may differ from the failed build state." in rendered

    conclusion = _section(rendered, "Jeffrey conclusion:", "Possible explanations:")
    assert (
        "Jenkins waited 1200s for the Kubernetes Job to complete, but it timed out "
        "during the build."
    ) in conclusion
    assert (
        "The Job pod is Completed now, so Kubernetes state changed after the Jenkins failure."
        in conclusion
    )
    assert "Collected current logs do not show suspicious error patterns." in conclusion
    assert (
        "The original timeout may have been caused by the Job finishing after Jenkins timeout"
        in conclusion
    )


def test_completed_job_status_does_not_produce_running_job_conclusion(
    tmp_path: Path,
    monkeypatch,
) -> None:
    log_path = _write_failed_job_log(tmp_path)
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(
        subprocess,
        "run",
        lambda command, **kwargs: _completed_job(command, pod_status="Completed"),
    )

    result = investigate_build_log(log_path)
    output = StringIO()
    console = Console(file=output, force_terminal=False)
    print_report(result, console=console)

    conclusion = _section(
        _normalized_output(output),
        "Jeffrey conclusion:",
        "Possible explanations:",
    )
    assert "The Job pod is still Running." not in conclusion
    assert (
        "The Job did not fail; it simply did not finish within the configured timeout."
        not in conclusion
    )


def test_completed_job_conclusion_does_not_repeat_log_status_lines(
    tmp_path: Path,
    monkeypatch,
) -> None:
    log_path = _write_failed_job_log(tmp_path)
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(
        subprocess,
        "run",
        lambda command, **kwargs: _completed_job(command, pod_status="Completed"),
    )

    result = investigate_build_log(log_path)
    output = StringIO()
    console = Console(file=output, force_terminal=False)
    print_report(result, console=console)

    rendered = _normalized_output(output)
    conclusion = _section(rendered, "Jeffrey conclusion:", "Possible explanations:")
    assert "Job pod logs were collected" in rendered
    assert "Job pod logs were collected" not in conclusion
    assert "Previous logs were not available" not in conclusion
    assert "Jeffrey found the Job pod and analyzed its logs." not in conclusion


def test_completed_job_timeout_shows_possible_explanations_and_warning(
    tmp_path: Path,
    monkeypatch,
) -> None:
    log_path = _write_failed_job_log(tmp_path, timestamp="2026-07-09T18:32:42Z")
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(
        subprocess,
        "run",
        lambda command, **kwargs: _completed_job(command, pod_status="Completed"),
    )

    result = investigate_build_log(log_path)
    output = StringIO()
    console = Console(file=output, force_terminal=False)
    print_report(result, console=console)

    rendered = _normalized_output(output)
    assert "Possible explanations:" in rendered
    assert "The Job completed after Jenkins had already timed out." in rendered
    assert "Kubernetes reported completion too late for the Jenkins wait timeout." in rendered
    assert "Jenkins and current Kubernetes state are from different moments in time." in rendered
    assert "Warning:" in rendered
    assert "Current Job/Pod state may differ from the failed build state." in rendered


def test_completed_job_timeout_still_shows_clean_log_excerpt(
    tmp_path: Path,
    monkeypatch,
) -> None:
    log_path = _write_failed_job_log(tmp_path)
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(
        subprocess,
        "run",
        lambda command, **kwargs: _completed_job(command, pod_status="Completed"),
    )

    result = investigate_build_log(log_path)
    output = StringIO()
    console = Console(file=output, force_terminal=False)
    print_report(result, console=console)

    rendered = _normalized_output(output)
    assert "Relevant log excerpts:" in rendered
    assert (
        "Job pod logs were collected for pod/data-job-abc, but no suspicious error "
        "patterns were detected."
    ) in rendered


def test_failed_job_conclusion_says_pod_failed(tmp_path: Path, monkeypatch) -> None:
    log_path = _write_failed_job_log(tmp_path)
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(subprocess, "run", _completed_job)

    result = investigate_build_log(log_path)
    output = StringIO()
    console = Console(file=output, force_terminal=False)
    print_report(result, console=console)

    conclusion = _section(output.getvalue(), "Jeffrey conclusion:", "Warning:")
    assert "The Job pod failed before completion." in conclusion
    assert "Jeffrey found the Job pod and analyzed its logs." not in conclusion


def test_suspicious_job_logs_are_referenced_semantically_in_conclusion(
    tmp_path: Path,
    monkeypatch,
) -> None:
    log_path = _write_failed_job_log(tmp_path)
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(
        subprocess,
        "run",
        lambda command, **kwargs: _completed_job(command, logs="panic recovered on /job/run\n"),
    )

    result = investigate_build_log(log_path)
    output = StringIO()
    console = Console(file=output, force_terminal=False)
    print_report(result, console=console)

    rendered = output.getvalue()
    conclusion = _section(rendered, "Jeffrey conclusion:", "Warning:")
    assert "Job pod logs show panic recovery events." in conclusion
    assert "The Job likely timed out because the command was unstable" in conclusion
    assert "panic recovered on /job/run" not in conclusion
    assert "panic recovered on /job/run" in rendered


def test_automatically_attempts_kubernetes_investigation_when_rollout_timeout_detected(
    tmp_path: Path,
    monkeypatch,
) -> None:
    log_path = _write_failed_rollout_log(tmp_path)
    monkeypatch.chdir(tmp_path)
    commands = []

    def fake_run(command, **kwargs):
        commands.append(command)
        return _completed(command)

    monkeypatch.setattr(subprocess, "run", fake_run)

    result = investigate_build_log(log_path)

    assert result.k8s_evidence is not None
    assert ["kubectl", "describe", "deployment", "web-app", "-n", "demo"] in commands


def test_jenkins_rollout_values_are_stored_and_reused(tmp_path: Path, monkeypatch) -> None:
    log_path = _write_failed_rollout_log(tmp_path)
    monkeypatch.chdir(tmp_path)
    commands = []

    def fake_run(command, **kwargs):
        commands.append(command)
        return _completed(command)

    monkeypatch.setattr(subprocess, "run", fake_run)

    result = investigate_build_log(log_path)

    assert result.rollout_context is not None
    assert result.rollout_context.namespace == "demo"
    assert result.rollout_context.deployment == "web-app"
    assert result.rollout_context.timeout == "150s"
    assert result.rollout_context.command == ROLLOUT_COMMAND
    assert ["kubectl", "get", "deployment", "web-app", "-n", "demo", "-o", "json"] in commands


def test_does_not_attempt_kubernetes_investigation_for_successful_build(
    tmp_path: Path,
    monkeypatch,
) -> None:
    log_path = tmp_path / "success.log"
    log_path.write_text(
        "\n".join(
            [
                "[Pipeline] { (Deploy)",
                f"[2026-07-06T16:41:07.946Z] + {ROLLOUT_COMMAND}",
                '[2026-07-06T16:41:30.471Z] deployment "web-app" successfully rolled out',
                "Finished: SUCCESS",
            ]
        ),
        encoding="utf-8",
    )

    def fake_run(*args, **kwargs):
        raise AssertionError("kubectl should not be called for successful builds")

    monkeypatch.setattr(subprocess, "run", fake_run)

    result = investigate_build_log(log_path)

    assert result.is_success is True
    assert result.k8s_evidence is None


def test_no_k8s_disables_kubernetes_investigation(tmp_path: Path, monkeypatch) -> None:
    log_path = _write_failed_rollout_log(tmp_path)

    def fake_run(*args, **kwargs):
        raise AssertionError("kubectl should not be called when collect_k8s is false")

    monkeypatch.setattr(subprocess, "run", fake_run)

    result = investigate_build_log(log_path, collect_k8s=False)

    assert result.k8s_evidence is None


def test_incomplete_jenkins_log_does_not_crash_or_collect_kubernetes(
    tmp_path: Path,
    monkeypatch,
) -> None:
    log_path = tmp_path / "running.log"
    log_path.write_text(
        "\n".join(
            [
                "[Pipeline] { (Deploy)",
                f"[2026-07-06T13:36:20.261Z] + {ROLLOUT_COMMAND}",
                'Waiting for deployment "web-app" rollout to finish...',
            ]
        ),
        encoding="utf-8",
    )

    def fake_run(*args, **kwargs):
        raise AssertionError("kubectl should not be called while no failure was detected")

    monkeypatch.setattr(subprocess, "run", fake_run)

    result = investigate_build_log(log_path)
    output = StringIO()
    console = Console(file=output, force_terminal=False)
    print_report(result, console=console)

    rendered = output.getvalue()
    assert result.status == "running"
    assert result.k8s_evidence is None
    assert "Jenkins log appears incomplete" in rendered
    assert 'Waiting for deployment "web-app" rollout to finish' in rendered


def test_crash_loop_backoff_refines_root_cause(tmp_path: Path, monkeypatch) -> None:
    log_path = _write_failed_rollout_log(tmp_path)
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(subprocess, "run", _fake_run_with_signal("CrashLoopBackOff"))

    result = investigate_build_log(log_path)

    assert result.likely_root_cause is not None
    assert result.likely_root_cause.root_cause == (
        "Deployment rollout timed out because one or more pods are crashing after startup."
    )


def test_module_not_found_in_previous_logs_refines_root_cause(tmp_path: Path, monkeypatch) -> None:
    log_path = _write_failed_rollout_log(tmp_path)
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(subprocess, "run", _fake_run_with_signal("ModuleNotFoundError"))

    result = investigate_build_log(log_path)

    assert result.likely_root_cause is not None
    assert result.likely_root_cause.root_cause == (
        "Deployment rollout timed out because the application failed to start due to "
        "a missing Python module."
    )
    assert any(
        insight.matched_pattern == "ModuleNotFoundError"
        for insight in result.k8s_evidence.log_insights
    )


def test_image_pull_backoff_refines_root_cause(tmp_path: Path, monkeypatch) -> None:
    log_path = _write_failed_rollout_log(tmp_path)
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(subprocess, "run", _fake_run_with_signal("ImagePullBackOff"))

    result = investigate_build_log(log_path)

    assert result.likely_root_cause is not None
    assert result.likely_root_cause.root_cause == (
        "Deployment rollout timed out because Kubernetes could not pull the Docker image."
    )


def test_traceback_in_logs_produces_log_insight(tmp_path: Path, monkeypatch) -> None:
    log_path = _write_failed_rollout_log(tmp_path)
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(subprocess, "run", _fake_run_with_signal("Traceback most recent call last"))

    result = investigate_build_log(log_path)

    assert result.k8s_evidence is not None
    assert result.k8s_evidence.log_insights[0].matched_pattern == "Traceback"


def test_connection_refused_in_logs_produces_log_insight_and_refines_root_cause(
    tmp_path: Path,
    monkeypatch,
) -> None:
    log_path = _write_failed_rollout_log(tmp_path)
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(subprocess, "run", _fake_run_with_signal("connection refused"))

    result = investigate_build_log(log_path)

    assert result.likely_root_cause is not None
    assert result.likely_root_cause.root_cause == (
        "Deployment rollout timed out because application logs show refused connections."
    )
    assert any(
        insight.matched_pattern == "connection refused"
        for insight in result.k8s_evidence.log_insights
    )


def test_clean_logs_report_no_known_error_patterns(tmp_path: Path, monkeypatch) -> None:
    log_path = _write_failed_rollout_log(tmp_path)
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(subprocess, "run", _fake_run_with_clean_logs)

    result = investigate_build_log(log_path)
    output = StringIO()
    console = Console(file=output, force_terminal=False)
    print_report(result, console=console)

    assert "no suspicious application log lines were detected" in _normalized_output(output)


def test_no_matched_pods_reports_logs_could_not_be_analyzed(
    tmp_path: Path,
    monkeypatch,
) -> None:
    log_path = _write_failed_rollout_log(tmp_path)
    monkeypatch.chdir(tmp_path)

    def fake_run(command, **kwargs):
        if command[:4] == ["kubectl", "get", "pods", "-n"]:
            if "-o" in command:
                return subprocess.CompletedProcess(command, 0, stdout='{"items":[]}', stderr="")
            return subprocess.CompletedProcess(
                command,
                0,
                stdout="NAME READY STATUS RESTARTS AGE\n",
                stderr="",
            )
        return _completed(command)

    monkeypatch.setattr(subprocess, "run", fake_run)

    result = investigate_build_log(log_path)
    output = StringIO()
    console = Console(file=output, force_terminal=False)
    print_report(result, console=console)

    assert "pod logs could not be analyzed" in _normalized_output(output)


def test_application_logs_unavailable_are_reported(tmp_path: Path, monkeypatch) -> None:
    log_path = _write_failed_rollout_log(tmp_path)
    monkeypatch.chdir(tmp_path)

    def fake_run(command, **kwargs):
        if command[:3] == ["kubectl", "logs", "web-app-abc-123"]:
            return subprocess.CompletedProcess(command, 1, stdout="", stderr="logs failed")
        return _completed(command)

    monkeypatch.setattr(subprocess, "run", fake_run)

    result = investigate_build_log(log_path)
    output = StringIO()
    console = Console(file=output, force_terminal=False)
    print_report(result, console=console)

    rendered = output.getvalue()
    assert "Current logs were not available for pod/web-app-abc-123." in rendered
    assert "pod_web-app-abc-123_logs.txt" not in rendered


def test_probe_configuration_lines_do_not_create_log_insights() -> None:
    evidence = KubernetesEvidence(
        namespace="demo",
        deployment="web-app",
        selected_pods=["web-app-abc-123"],
        pod_descriptions={
            "web-app-abc-123": CommandResult(
                command=["kubectl", "describe", "pod", "web-app-abc-123"],
                exit_code=0,
                stdout=(
                    "Liveness: http-get http://:8080/health delay=10s timeout=1s\n"
                    "Readiness: http-get http://:8080/ready delay=5s timeout=1s\n"
                    "Startup: http-get http://:8080/start delay=1s timeout=1s\n"
                ),
            )
        },
        pod_logs={
            "web-app-abc-123": CommandResult(
                command=["kubectl", "logs", "web-app-abc-123"],
                exit_code=0,
                stdout="Application started\n",
            )
        },
    )

    insights = analyze_log_insights(evidence)

    assert all(insight.source != "describe" for insight in insights)
    assert insights[0].matched_pattern == "clean logs"


def test_readiness_probe_failure_in_describe_creates_log_insight() -> None:
    evidence = KubernetesEvidence(
        namespace="demo",
        deployment="web-app",
        selected_pods=["web-app-abc-123"],
        pod_descriptions={
            "web-app-abc-123": CommandResult(
                command=["kubectl", "describe", "pod", "web-app-abc-123"],
                exit_code=0,
                stdout="Warning Unhealthy Readiness probe failed: HTTP probe failed\n",
            )
        },
        pod_logs={
            "web-app-abc-123": CommandResult(
                command=["kubectl", "logs", "web-app-abc-123"],
                exit_code=0,
                stdout="Application started\n",
            )
        },
    )

    insights = analyze_log_insights(evidence)

    assert any(
        insight.source == "describe" and insight.matched_pattern == "readiness probe failed"
        for insight in insights
    )


def test_foreign_namespace_events_do_not_refine_root_cause(tmp_path: Path, monkeypatch) -> None:
    log_path = _write_failed_rollout_log(tmp_path)
    monkeypatch.chdir(tmp_path)

    def fake_run(command, **kwargs):
        if command[:3] == ["kubectl", "get", "events"]:
            return subprocess.CompletedProcess(
                command,
                0,
                stdout=(
                    "57m Warning Unhealthy pod/database-0 Readiness probe failed\n"
                    "4m Warning Unhealthy pod/other-api-123 Readiness probe failed\n"
                ),
                stderr="",
            )
        return _completed(command)

    monkeypatch.setattr(subprocess, "run", fake_run)

    result = investigate_build_log(log_path)

    assert result.likely_root_cause is not None
    assert result.likely_root_cause.root_cause == "Deployment rollout timed out"
    assert all("database-0" not in line for line in result.likely_root_cause.evidence)
    assert all("other-api-123" not in line for line in result.likely_root_cause.evidence)
    namespace_events = (tmp_path / ".jeffrey" / "namespace_events.txt").read_text(
        encoding="utf-8"
    )
    assert "database-0" in namespace_events
    assert "other-api-123" in namespace_events
    assert "Uncorrelated raw namespace event context" in namespace_events


def test_pod_specific_events_for_selected_pod_are_included(tmp_path: Path, monkeypatch) -> None:
    log_path = _write_failed_rollout_log(tmp_path)
    monkeypatch.chdir(tmp_path)

    def fake_run(command, **kwargs):
        if (
            command[:3] == ["kubectl", "get", "events"]
            and any("involvedObject.name=web-app-abc-123" in part for part in command)
        ):
            return subprocess.CompletedProcess(
                command,
                0,
                stdout="4m Warning Unhealthy pod/web-app-abc-123 Readiness probe failed\n",
                stderr="",
            )
        if command[:3] == ["kubectl", "get", "events"]:
            return subprocess.CompletedProcess(
                command,
                0,
                stdout=(
                    "57m Warning Unhealthy pod/database-0 Readiness probe failed\n"
                    "4m Warning Unhealthy pod/other-api-123 Readiness probe failed\n"
                ),
                stderr="",
            )
        return _completed(command)

    monkeypatch.setattr(subprocess, "run", fake_run)

    result = investigate_build_log(log_path)

    assert result.likely_root_cause is not None
    assert result.likely_root_cause.root_cause == (
        "Deployment rollout timed out because pods did not pass readiness checks."
    )
    assert any("web-app-abc-123" in line for line in result.likely_root_cause.evidence)
    assert all("database-0" not in line for line in result.likely_root_cause.evidence)
    assert all("other-api-123" not in line for line in result.likely_root_cause.evidence)


def test_selector_from_deployment_json_is_used_for_pod_lookup(
    tmp_path: Path,
    monkeypatch,
) -> None:
    log_path = _write_failed_rollout_log(tmp_path)
    monkeypatch.chdir(tmp_path)
    commands = []

    def fake_run(command, **kwargs):
        commands.append(command)
        return _completed(command)

    monkeypatch.setattr(subprocess, "run", fake_run)

    result = investigate_build_log(log_path)

    assert result.k8s_evidence is not None
    assert result.k8s_evidence.selector == {"app": "web-app"}
    assert result.k8s_evidence.fallback_pod_matching_used is False
    assert [
        "kubectl",
        "get",
        "pods",
        "-n",
        "demo",
        "-l",
        "app=web-app",
        "-o",
        "json",
    ] in commands


def test_fallback_name_matching_is_used_only_when_selector_lookup_fails(
    tmp_path: Path,
    monkeypatch,
) -> None:
    log_path = _write_failed_rollout_log(tmp_path)
    monkeypatch.chdir(tmp_path)

    def fake_run(command, **kwargs):
        if (
            command[:4] == ["kubectl", "get", "pods", "-n"]
            and "-l" in command
            and "-o" in command
        ):
            return subprocess.CompletedProcess(command, 0, stdout='{"items":[]}', stderr="")
        return _completed(command)

    monkeypatch.setattr(subprocess, "run", fake_run)

    result = investigate_build_log(log_path)

    assert result.k8s_evidence is not None
    assert result.k8s_evidence.fallback_pod_matching_used is True
    assert result.k8s_evidence.selected_pods == ["web-app-abc-123"]


def test_default_output_says_no_correlated_failure_for_unrelated_events(
    tmp_path: Path,
    monkeypatch,
) -> None:
    log_path = _write_failed_rollout_log(tmp_path)
    monkeypatch.chdir(tmp_path)

    def fake_run(command, **kwargs):
        if command[:3] == ["kubectl", "get", "events"]:
            return subprocess.CompletedProcess(
                command,
                0,
                stdout="4m Warning Unhealthy pod/other-api-123 Readiness probe failed\n",
                stderr="",
            )
        return _completed(command)

    monkeypatch.setattr(subprocess, "run", fake_run)
    result = investigate_build_log(log_path)
    output = StringIO()
    console = Console(file=output, force_terminal=False)

    print_report(result, console=console)

    rendered = _normalized_output(output)
    assert "No correlated Kubernetes pod failure was found in current cluster state." in rendered
    assert "Kubernetes namespace events output: available" not in rendered
    assert "other-api-123" not in rendered


def test_debug_output_shows_investigation_steps(tmp_path: Path, monkeypatch) -> None:
    log_path = _write_failed_rollout_log(tmp_path)
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(subprocess, "run", _fake_run_with_signal("CrashLoopBackOff"))
    output = StringIO()
    console = Console(file=output, force_terminal=False)

    investigate_build_log(log_path, debug=True, console=console)

    rendered = _normalized_output(output)
    assert "[DEBUG] Reading Jenkins log..." in rendered
    assert "[DEBUG] Extracted namespace:" in rendered
    assert "[DEBUG] Extracted deployment:" in rendered
    assert "[DEBUG] Running:" in rendered
    assert "CrashLoopBackOff" in rendered


def test_show_commands_prints_shell_commands(tmp_path: Path, monkeypatch) -> None:
    log_path = _write_failed_rollout_log(tmp_path)
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(subprocess, "run", _fake_run_with_signal("CrashLoopBackOff"))
    output = StringIO()
    console = Console(file=output, force_terminal=False)

    investigate_build_log(log_path, show_commands=True, console=console)

    rendered = output.getvalue()
    assert "$ kubectl get pods -n demo -l app=web-app -o json" in rendered
    assert "$ kubectl describe deployment web-app -n demo" in rendered
    assert "kubectl found" not in rendered
    assert "[DEBUG]" not in rendered


def test_default_output_hides_preflight_noise_and_previous_logs_bad_request(
    tmp_path: Path,
    monkeypatch,
) -> None:
    log_path = _write_failed_rollout_log(tmp_path)
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(subprocess, "run", _fake_run_with_previous_logs_bad_request)
    result = investigate_build_log(log_path)
    output = StringIO()
    console = Console(file=output, force_terminal=False)

    print_report(result, console=console)

    rendered = output.getvalue()
    assert "Jeffrey investigation report" in rendered
    assert "kubectl found" not in rendered
    assert "kubeconfig loaded" not in rendered
    assert "current context" not in rendered
    assert "Deployment described" not in rendered
    assert "Pod logs collected" not in rendered
    assert "previous terminated container" not in rendered
    assert "Error from server (BadRequest)" not in rendered
    assert "Raw evidence saved to:" in rendered


def test_previous_logs_unavailable_is_log_insight_not_next_step(
    tmp_path: Path,
    monkeypatch,
) -> None:
    log_path = _write_failed_rollout_log(tmp_path)
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(subprocess, "run", _fake_run_with_previous_logs_bad_request)
    result = investigate_build_log(log_path)
    output = StringIO()
    console = Console(file=output, force_terminal=False)

    print_report(result, console=console)

    rendered = output.getvalue()
    assert "Previous logs were not available for pod/web-app-abc-123." in rendered
    assert "What to check next:" not in rendered


def test_default_output_shows_max_three_log_insights(tmp_path: Path, monkeypatch) -> None:
    log_path = _write_failed_rollout_log(tmp_path)
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(subprocess, "run", _fake_run_with_many_log_errors)
    result = investigate_build_log(log_path)
    output = StringIO()
    console = Console(file=output, force_terminal=False)

    print_report(result, console=console)

    rendered = output.getvalue()
    log_section = rendered.split("Relevant log excerpts:", 1)[1].split(
        "Raw evidence saved to:",
        1,
    )[0]
    log_insight_lines = [
        line
        for line in log_section.splitlines()
        if line.startswith("- pod/") or line.startswith("- Logs")
    ]
    assert len(log_insight_lines) <= 3


def test_duplicate_generic_kubernetes_evidence_lines_are_removed(
    tmp_path: Path,
    monkeypatch,
) -> None:
    log_path = _write_failed_rollout_log(tmp_path)
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(subprocess, "run", _fake_run_with_clean_logs)
    result = investigate_build_log(log_path)
    output = StringIO()
    console = Console(file=output, force_terminal=False)

    print_report(result, console=console)

    rendered = output.getvalue()
    assert rendered.count("No correlated Kubernetes pod failure was found") <= 1
    assert "Kubernetes evidence was collected, but no correlated pod/deployment" not in rendered


def test_default_output_has_conclusion_without_manual_raw_evidence_steps(
    tmp_path: Path,
    monkeypatch,
) -> None:
    log_path = _write_failed_rollout_log(tmp_path)
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(subprocess, "run", _fake_run_with_clean_logs)
    result = investigate_build_log(log_path)
    output = StringIO()
    console = Console(file=output, force_terminal=False)

    print_report(result, console=console)

    rendered = output.getvalue()
    assert "Jeffrey conclusion:" in rendered
    assert "What to check next:" not in rendered
    assert "Open .jeffrey" not in rendered
    assert "Raw evidence saved to:" in rendered


def test_application_log_analysis_does_not_include_kubernetes_signal_lines(
    tmp_path: Path,
    monkeypatch,
) -> None:
    log_path = _write_failed_rollout_log(tmp_path)
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(
        subprocess,
        "run",
        _fake_run_with_readiness_signal("context deadline exceeded"),
    )
    result = investigate_build_log(log_path)
    output = StringIO()
    console = Console(file=output, force_terminal=False)

    print_report(result, console=console)

    rendered = output.getvalue()
    app_section = rendered.split("Relevant log excerpts:", 1)[1].split(
        "Jeffrey conclusion:",
        1,
    )[0]
    assert "Readiness probe failed" not in app_section
    assert "context deadline exceeded" not in app_section
    assert "no suspicious application log lines were detected" in " ".join(
        app_section.split()
    )


def test_kubernetes_signal_includes_readiness_failures(tmp_path: Path, monkeypatch) -> None:
    log_path = _write_failed_rollout_log(tmp_path)
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(
        subprocess,
        "run",
        _fake_run_with_readiness_signal("context deadline exceeded"),
    )
    result = investigate_build_log(log_path)
    output = StringIO()
    console = Console(file=output, force_terminal=False)

    print_report(result, console=console)

    rendered = output.getvalue()
    assert "Kubernetes signal:" in rendered
    assert "readiness probe failed: context deadline exceeded" in rendered


def test_readiness_connection_refused_refines_root_cause(tmp_path: Path, monkeypatch) -> None:
    log_path = _write_failed_rollout_log(tmp_path)
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(
        subprocess,
        "run",
        _fake_run_with_readiness_signal("connection refused"),
    )

    result = investigate_build_log(log_path)

    assert result.likely_root_cause is not None
    assert result.likely_root_cause.root_cause == (
        "Deployment rollout timed out because the application was not accepting "
        "connections on the readiness port."
    )


def test_readiness_context_deadline_refines_root_cause(tmp_path: Path, monkeypatch) -> None:
    log_path = _write_failed_rollout_log(tmp_path)
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(
        subprocess,
        "run",
        _fake_run_with_readiness_signal("context deadline exceeded"),
    )

    result = investigate_build_log(log_path)

    assert result.likely_root_cause is not None
    assert result.likely_root_cause.root_cause == (
        "Deployment rollout timed out because readiness checks timed out before "
        "the application responded."
    )


def test_panic_lines_rank_above_generic_errors() -> None:
    evidence = _evidence_with_logs(
        "Error: temporary backend error\npanic recovered on /service/Method\n"
    )

    excerpts = extract_log_excerpts(evidence)

    assert excerpts[0].label == "PANIC"
    assert excerpts[0].score > excerpts[1].score


def test_module_not_found_excerpt_is_ranked_high() -> None:
    evidence = _evidence_with_logs("Warning: retrying\nModuleNotFoundError: No module named app\n")

    excerpts = extract_log_excerpts(evidence)

    assert excerpts[0].label == "MODULE_NOT_FOUND"
    assert excerpts[0].score == 96


def test_duplicate_log_excerpts_are_removed() -> None:
    evidence = _evidence_with_logs("Error: failed to connect\nError: failed to connect\n")

    excerpts = [excerpt for excerpt in extract_log_excerpts(evidence) if excerpt.score > 0]

    assert len(excerpts) == 1


def test_default_output_shows_max_three_relevant_log_excerpts(
    tmp_path: Path,
    monkeypatch,
) -> None:
    log_path = _write_failed_rollout_log(tmp_path)
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(
        subprocess,
        "run",
        _fake_run_with_application_logs(
            "panic recovered on /service/A\n"
            "Traceback most recent call last\n"
            "ModuleNotFoundError: No module named app\n"
            "connection refused\n"
            "Error: extra detail\n"
        ),
    )
    result = investigate_build_log(log_path)
    output = StringIO()
    console = Console(file=output, force_terminal=False)

    print_report(result, console=console)

    rendered = output.getvalue()
    log_section = rendered.split("Relevant log excerpts:", 1)[1].split(
        "Jeffrey conclusion:",
        1,
    )[0]
    assert log_section.count("- [") == 3
    assert "More log excerpts saved to:" in rendered


def test_relevant_log_excerpts_exclude_kubernetes_sources(tmp_path: Path, monkeypatch) -> None:
    log_path = _write_failed_rollout_log(tmp_path)
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(
        subprocess,
        "run",
        _fake_run_with_readiness_signal("context deadline exceeded"),
    )
    result = investigate_build_log(log_path)
    output = StringIO()
    console = Console(file=output, force_terminal=False)

    print_report(result, console=console)

    log_section = output.getvalue().split("Relevant log excerpts:", 1)[1].split(
        "Jeffrey conclusion:",
        1,
    )[0]
    assert "Readiness probe failed" not in log_section
    assert "context deadline exceeded" not in log_section


def test_clean_logs_print_clear_excerpt_message(tmp_path: Path, monkeypatch) -> None:
    log_path = _write_failed_rollout_log(tmp_path)
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(subprocess, "run", _fake_run_with_clean_logs)
    result = investigate_build_log(log_path)
    output = StringIO()
    console = Console(file=output, force_terminal=False)

    print_report(result, console=console)

    assert "no suspicious application log lines were detected" in _normalized_output(output)


def test_unavailable_logs_print_clear_excerpt_messages(tmp_path: Path, monkeypatch) -> None:
    log_path = _write_failed_rollout_log(tmp_path)
    monkeypatch.chdir(tmp_path)

    def fake_run(command, **kwargs):
        if command[:3] == ["kubectl", "logs", "web-app-abc-123"]:
            return subprocess.CompletedProcess(command, 1, stdout="", stderr="logs failed")
        return _completed(command)

    monkeypatch.setattr(subprocess, "run", fake_run)
    result = investigate_build_log(log_path)
    output = StringIO()
    console = Console(file=output, force_terminal=False)

    print_report(result, console=console)

    rendered = output.getvalue()
    assert "Current logs were not available for pod/web-app-abc-123." in rendered
    assert "Previous logs were not available for pod/web-app-abc-123." in rendered


def test_panic_excerpts_refine_root_cause(tmp_path: Path, monkeypatch) -> None:
    log_path = _write_failed_rollout_log(tmp_path)
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(
        subprocess,
        "run",
        _fake_run_with_application_logs("panic recovered on /service/Method\n"),
    )

    result = investigate_build_log(log_path)

    assert result.likely_root_cause is not None
    assert "panic recovery events" in result.likely_root_cause.root_cause


def test_long_log_excerpts_are_trimmed(tmp_path: Path, monkeypatch) -> None:
    log_path = _write_failed_rollout_log(tmp_path)
    monkeypatch.chdir(tmp_path)
    long_line = "Error: " + ("x" * 240)
    monkeypatch.setattr(subprocess, "run", _fake_run_with_application_logs(long_line))
    result = investigate_build_log(log_path)
    output = StringIO()
    console = Console(file=output, force_terminal=False)

    print_report(result, console=console)

    rendered = output.getvalue()
    assert "..." in rendered
    assert "x" * 220 not in rendered


def test_stack_frame_lines_rank_below_panic_lines() -> None:
    evidence = _evidence_with_logs(
        "go.example.com/project/pkg/http.ProcessError(...)\n"
        "panic recovered on /service/Method\n"
    )

    excerpts = extract_log_excerpts(evidence)

    assert excerpts[0].label == "PANIC"
    assert any(excerpt.label == "STACK" and excerpt.score == 25 for excerpt in excerpts)


def test_raw_evidence_is_still_saved_with_relevant_excerpts(
    tmp_path: Path,
    monkeypatch,
) -> None:
    log_path = _write_failed_rollout_log(tmp_path)
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(
        subprocess,
        "run",
        _fake_run_with_application_logs("panic recovered on /service/Method\n"),
    )

    investigate_build_log(log_path)

    assert (tmp_path / ".jeffrey" / "pod_web-app-abc-123_logs.txt").exists()


def test_old_jenkins_timestamp_produces_current_state_warning(
    tmp_path: Path,
    monkeypatch,
) -> None:
    log_path = _write_failed_rollout_log(tmp_path, timestamp="2020-01-01T00:00:00.000Z")
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(subprocess, "run", _fake_run_with_clean_logs)

    result = investigate_build_log(log_path)
    output = StringIO()
    console = Console(file=output, force_terminal=False)
    print_report(result, console=console)

    rendered = output.getvalue()
    assert "Warning:" in rendered
    assert "2020-01-01T00:00:00Z" in rendered


def test_debug_output_contains_preflight_details_and_command_errors(
    tmp_path: Path,
    monkeypatch,
) -> None:
    log_path = _write_failed_rollout_log(tmp_path)
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(subprocess, "run", _fake_run_with_previous_logs_bad_request)
    output = StringIO()
    console = Console(file=output, force_terminal=False)

    investigate_build_log(log_path, debug=True, console=console)

    rendered = output.getvalue()
    assert "kubectl found" in rendered
    assert "current context:" in rendered
    assert "kubectl stderr:" in rendered
    assert "previous terminated container" in rendered


def test_verbose_output_contains_compact_summary(tmp_path: Path, monkeypatch) -> None:
    log_path = _write_failed_rollout_log(tmp_path)
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(subprocess, "run", _fake_run_with_signal("CrashLoopBackOff"))
    result = investigate_build_log(log_path)
    output = StringIO()
    console = Console(file=output, force_terminal=False)

    print_report(result, console=console, verbose=True)

    rendered = output.getvalue()
    assert "Investigation summary" in rendered
    assert "Pods investigated:" in rendered
    assert "Duration:" in rendered


def test_raw_evidence_stores_command_errors(tmp_path: Path, monkeypatch) -> None:
    log_path = _write_failed_rollout_log(tmp_path)
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(subprocess, "run", _fake_run_with_previous_logs_bad_request)

    investigate_build_log(log_path)

    previous_logs = (tmp_path / ".jeffrey" / "previous_logs.txt").read_text(encoding="utf-8")
    assert "previous terminated container" in previous_logs


def test_save_report_writes_markdown(tmp_path: Path, monkeypatch) -> None:
    log_path = _write_failed_rollout_log(tmp_path)
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(subprocess, "run", _fake_run_with_signal("CrashLoopBackOff"))
    result = investigate_build_log(log_path)
    report_path = tmp_path / "report.md"

    save_markdown_report(result, report_path)

    content = report_path.read_text(encoding="utf-8")
    assert "# Jeffrey Investigation Report" in content
    assert "## Likely root cause" in content
    assert "## Executed commands" in content


def test_save_raw_evidence_writes_files(tmp_path: Path) -> None:
    evidence = KubernetesEvidence(
        namespace="demo",
        deployment="web-app",
        deployment_description=CommandResult(
            command=["kubectl", "describe", "deployment", "web-app"],
            exit_code=0,
            stdout="deployment details",
        ),
        deployment_json=CommandResult(
            command=["kubectl", "get", "deployment", "web-app", "-o", "json"],
            exit_code=0,
            stdout='{"spec": {"selector": {"matchLabels": {"app": "web-app"}}}}',
        ),
        pods_json=CommandResult(
            command=["kubectl", "get", "pods", "-o", "json"],
            exit_code=0,
            stdout='{"items": []}',
        ),
        pods_output=CommandResult(
            command=["kubectl", "get", "pods"],
            exit_code=0,
            stdout="pods",
        ),
        namespace_events_output=CommandResult(
            command=["kubectl", "get", "events"],
            exit_code=0,
            stdout="events",
        ),
        pod_descriptions={
            "web-app-abc-123": CommandResult(
                command=["kubectl", "describe", "pod", "web-app-abc-123"],
                exit_code=0,
                stdout="pod describe",
            )
        },
        pod_logs={
            "web-app-abc-123": CommandResult(
                command=["kubectl", "logs", "web-app-abc-123"],
                exit_code=0,
                stdout="logs",
            )
        },
        pod_previous_logs={
            "web-app-abc-123": CommandResult(
                command=["kubectl", "logs", "web-app-abc-123", "--previous"],
                exit_code=0,
                stdout="previous logs",
            )
        },
    )

    output_dir = save_raw_evidence(evidence, tmp_path / ".jeffrey")

    assert (output_dir / "deployment.json").read_text(encoding="utf-8")
    assert (
        output_dir / "deployment_describe.txt"
    ).read_text(encoding="utf-8") == "deployment details"
    assert (output_dir / "pods.json").read_text(encoding="utf-8")
    assert (output_dir / "pods.txt").read_text(encoding="utf-8") == "pods"
    assert "events" in (output_dir / "namespace_events.txt").read_text(encoding="utf-8")
    assert "pod describe" in (output_dir / "pod_describe.txt").read_text(encoding="utf-8")
    assert (
        output_dir / "pod_web-app-abc-123_describe.txt"
    ).read_text(encoding="utf-8") == "pod describe"
    assert "logs" in (output_dir / "logs.txt").read_text(encoding="utf-8")
    assert "previous logs" in (output_dir / "previous_logs.txt").read_text(encoding="utf-8")


def test_missing_kubeconfig_is_recorded(tmp_path: Path, monkeypatch) -> None:
    log_path = _write_failed_rollout_log(tmp_path)
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("KUBECONFIG", str(tmp_path / "missing-config"))
    monkeypatch.setattr(subprocess, "run", _fake_run_with_signal("CrashLoopBackOff"))

    result = investigate_build_log(log_path)

    assert result.k8s_evidence is not None
    assert result.k8s_evidence.environment is not None
    assert result.k8s_evidence.environment.kubeconfig_loaded is False


def test_partial_kubectl_failures_do_not_stop_investigation(tmp_path: Path, monkeypatch) -> None:
    log_path = _write_failed_rollout_log(tmp_path)
    monkeypatch.chdir(tmp_path)

    def fake_run(command, **kwargs):
        if command[:3] == ["kubectl", "logs", "web-app-abc-123"]:
            return subprocess.CompletedProcess(command, 1, stdout="", stderr="logs failed")
        return _completed(command, signal="CrashLoopBackOff")

    monkeypatch.setattr(subprocess, "run", fake_run)

    result = investigate_build_log(log_path)

    assert result.k8s_evidence is not None
    assert result.k8s_evidence.pod_descriptions
    assert result.k8s_evidence.namespace_events_output is not None
    assert result.k8s_evidence.command_errors


def test_successful_rollout_still_reports_success(tmp_path: Path) -> None:
    log_path = tmp_path / "success.log"
    log_path.write_text(
        "\n".join(
            [
                "[Pipeline] { (Deploy)",
                f"[2026-07-06T16:41:07.946Z] + {ROLLOUT_COMMAND}",
                '[2026-07-06T16:41:30.471Z] deployment "web-app" successfully rolled out',
                "Finished: SUCCESS",
            ]
        ),
        encoding="utf-8",
    )

    result = investigate_build_log(log_path)

    assert result.is_success is True
    assert result.successful_rollouts[0].name == "web-app"


def _write_failed_rollout_log(
    tmp_path: Path,
    *,
    timestamp: str = "2026-07-06T13:36:20.261Z",
) -> Path:
    log_path = tmp_path / "failed.log"
    log_path.write_text(
        "\n".join(
            [
                "[Pipeline] { (Deploy)",
                f"[{timestamp}] + {ROLLOUT_COMMAND}",
                f"[{timestamp}] error: timed out waiting for the condition",
                "Finished: FAILURE",
            ]
        ),
        encoding="utf-8",
    )
    return log_path


def _write_failed_job_log(
    tmp_path: Path,
    *,
    timestamp: str = "2026-07-06T13:36:20.261Z",
) -> Path:
    log_path = tmp_path / "failed-job.log"
    log_path.write_text(
        "\n".join(
            [
                "[Pipeline] { (Deploy)",
                f"[{timestamp}] + {JOB_COMMAND}",
                (
                    f"[{timestamp}] error: timed out waiting for the condition "
                    "on jobs/data-job"
                ),
                "Finished: FAILURE",
            ]
        ),
        encoding="utf-8",
    )
    return log_path


def _fake_run_with_signal(signal: str):
    def fake_run(command, **kwargs):
        return _completed(command, signal=signal)

    return fake_run


def _completed(command: list[str], signal: str | None = None) -> subprocess.CompletedProcess:
    stdout = ""
    if command == ["kubectl", "config", "current-context"]:
        stdout = "demo-cluster\n"
    elif command[:5] == ["kubectl", "get", "deployment", "web-app", "-n"]:
        stdout = '{"spec": {"selector": {"matchLabels": {"app": "web-app"}}}}\n'
    elif (
        command[:4] == ["kubectl", "get", "pods", "-n"]
        and "-o" in command
        and "json" in command
    ):
        reason = ""
        if signal in {"CrashLoopBackOff", "ImagePullBackOff"}:
            reason = (
                ',"containerStatuses":[{"state":{"waiting":{"reason":"'
                f'{signal}"'
                "}}}]"
            )
        stdout = (
            '{"items":[{"metadata":{"name":"web-app-abc-123"},'
            f'"status":{{"phase":"Running"{reason}}}}}]}}\n'
        )
    elif command[:4] == ["kubectl", "get", "pods", "-n"]:
        stdout = "NAME READY STATUS RESTARTS AGE\nweb-app-abc-123 0/1 Running 0 2m\n"
        if signal == "ImagePullBackOff":
            stdout = (
                "NAME READY STATUS RESTARTS AGE\n"
                "web-app-abc-123 0/1 ImagePullBackOff 0 2m\n"
            )
    elif command[:4] == ["kubectl", "describe", "pod", "web-app-abc-123"]:
        stdout = signal or "Pod is pending"
    elif command[:3] == ["kubectl", "logs", "web-app-abc-123"]:
        if "--previous" in command and signal == "ModuleNotFoundError":
            stdout = "ModuleNotFoundError: No module named 'app.settings'\n"
        elif signal not in {"ImagePullBackOff", "ModuleNotFoundError"}:
            stdout = signal or ""
    elif command[:4] == ["kubectl", "describe", "deployment", "web-app"]:
        stdout = "Deployment web-app description\n"
    elif (
        command[:3] == ["kubectl", "get", "events"]
        and any("involvedObject.name=web-app-abc-123" in part for part in command)
    ):
        stdout = signal or "Normal pod event\n"
    elif command[:3] == ["kubectl", "get", "events"]:
        stdout = signal or "Normal rollout event\n"

    return subprocess.CompletedProcess(command, 0, stdout=stdout, stderr="")


def _completed_job(
    command: list[str],
    *,
    selector: bool = True,
    logs: str = "job started\n",
    pod_status: str = "Error",
    **kwargs,
) -> subprocess.CompletedProcess:
    stdout = ""
    if command == ["kubectl", "config", "current-context"]:
        stdout = "demo-cluster\n"
    elif command[:4] == ["kubectl", "describe", "job", "data-job"]:
        stdout = (
            "Name: data-job\n"
            "Completions: 1\n"
            "Parallelism: 1\n"
            "Pods Statuses: 0 Active / 0 Succeeded / 1 Failed\n"
        )
    elif command[:5] == ["kubectl", "get", "job", "data-job", "-n"]:
        if selector:
            stdout = (
                '{"spec":{"selector":{"matchLabels":{"controller-uid":"job-uid"}},'
                '"backoffLimit":6,"completions":1,"parallelism":1},'
                '"status":{"active":0,"failed":1,"succeeded":0}}'
            )
        else:
            stdout = '{"spec":{"backoffLimit":6},"status":{"failed":1}}'
    elif (
        command[:4] == ["kubectl", "get", "pods", "-n"]
        and "-o" in command
        and (
            "controller-uid=job-uid" in command
            or "job-name=data-job" in command
            or "batch.kubernetes.io/job-name=data-job" in command
        )
    ):
        if not selector and "controller-uid=job-uid" in command:
            stdout = '{"items":[]}'
        else:
            phase = "Running" if pod_status == "Running" else "Failed"
            if pod_status in {"Completed", "Succeeded"}:
                phase = "Succeeded"
            container_state = (
                '"state":{"running":{}}'
                if pod_status == "Running"
                else f'"state":{{"terminated":{{"reason":"{pod_status}"}}}}'
            )
            stdout = (
                '{"items":[{"metadata":{"name":"data-job-abc"},'
                f'"status":{{"phase":"{phase}",'
                f'"containerStatuses":[{{{container_state}}}]}}}}]}}'
            )
    elif command[:4] == ["kubectl", "get", "pods", "-n"]:
        stdout = f"NAME READY STATUS RESTARTS AGE\ndata-job-abc 0/1 {pod_status} 0 2m\n"
    elif command[:4] == ["kubectl", "describe", "pod", "data-job-abc"]:
        stdout = f"Name: data-job-abc\nStatus: {pod_status}\n"
    elif command[:3] == ["kubectl", "logs", "data-job-abc"]:
        stdout = "previous job log\n" if "--previous" in command else logs
    elif (
        command[:3] == ["kubectl", "get", "events"]
        and any("involvedObject.name=data-job-abc" in part for part in command)
    ):
        stdout = "Warning BackOff pod/data-job-abc Back-off restarting failed container\n"
    elif command[:3] == ["kubectl", "get", "events"]:
        stdout = "Warning Unhealthy pod/other-api-123 unrelated event\n"
    return subprocess.CompletedProcess(command, 0, stdout=stdout, stderr="")


def _fake_run_with_previous_logs_bad_request(
    command: list[str],
    **kwargs,
) -> subprocess.CompletedProcess:
    if command[:3] == ["kubectl", "logs", "web-app-abc-123"] and "--previous" in command:
        return subprocess.CompletedProcess(
            command,
            1,
            stdout="",
            stderr=(
                "Error from server (BadRequest): previous terminated container "
                "web-app in pod web-app-abc-123 not found"
            ),
        )
    return _completed(command)


def _fake_run_with_clean_logs(command: list[str], **kwargs) -> subprocess.CompletedProcess:
    if command[:3] == ["kubectl", "logs", "web-app-abc-123"]:
        return subprocess.CompletedProcess(command, 0, stdout="Application started\n", stderr="")
    if (
        command[:3] == ["kubectl", "get", "events"]
        and any("involvedObject.name=web-app-abc-123" in part for part in command)
    ):
        return subprocess.CompletedProcess(command, 0, stdout="", stderr="")
    return _completed(command)


def _fake_run_with_readiness_signal(reason: str):
    readiness_line = (
        'Warning Unhealthy pod/web-app-abc-123 Readiness probe failed: Get '
        f'"http://10.0.0.1:8011/status?readiness": {reason}\n'
    )

    def fake_run(command: list[str], **kwargs) -> subprocess.CompletedProcess:
        if command[:4] == ["kubectl", "describe", "pod", "web-app-abc-123"]:
            return subprocess.CompletedProcess(command, 0, stdout=readiness_line, stderr="")
        if (
            command[:3] == ["kubectl", "get", "events"]
            and any("involvedObject.name=web-app-abc-123" in part for part in command)
        ):
            return subprocess.CompletedProcess(command, 0, stdout=readiness_line, stderr="")
        if command[:3] == ["kubectl", "logs", "web-app-abc-123"]:
            return subprocess.CompletedProcess(
                command,
                0,
                stdout="Application started\n",
                stderr="",
            )
        return _completed(command)

    return fake_run


def _fake_run_with_application_logs(logs: str):
    def fake_run(command: list[str], **kwargs) -> subprocess.CompletedProcess:
        if command[:3] == ["kubectl", "logs", "web-app-abc-123"]:
            if "--previous" in command:
                return subprocess.CompletedProcess(
                    command,
                    1,
                    stdout="",
                    stderr="previous logs not found",
                )
            return subprocess.CompletedProcess(command, 0, stdout=logs, stderr="")
        return _completed(command)

    return fake_run


def _evidence_with_logs(logs: str) -> KubernetesEvidence:
    return KubernetesEvidence(
        namespace="demo",
        deployment="web-app",
        selected_pods=["web-app-abc-123"],
        pod_logs={
            "web-app-abc-123": CommandResult(
                command=["kubectl", "logs", "web-app-abc-123"],
                exit_code=0,
                stdout=logs,
            )
        },
        pod_previous_logs={
            "web-app-abc-123": CommandResult(
                command=["kubectl", "logs", "web-app-abc-123", "--previous"],
                exit_code=1,
                stderr="previous logs not found",
            )
        },
    )


def _fake_run_with_many_log_errors(command: list[str], **kwargs) -> subprocess.CompletedProcess:
    if command[:3] == ["kubectl", "logs", "web-app-abc-123"]:
        return subprocess.CompletedProcess(
            command,
            0,
            stdout=(
                "Traceback most recent call last\n"
                "ModuleNotFoundError: No module named app\n"
                "connection refused\n"
                "permission denied\n"
                "no space left on device\n"
            ),
            stderr="",
        )
    return _completed(command)


def _normalized_output(output: StringIO) -> str:
    return " ".join(output.getvalue().split())


def _section(rendered: str, start: str, end: str) -> str:
    if start not in rendered:
        return ""
    section = rendered.split(start, 1)[1]
    if end in section:
        section = section.split(end, 1)[0]
    return " ".join(section.split())
