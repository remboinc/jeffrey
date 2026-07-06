from __future__ import annotations

import subprocess
from io import StringIO
from pathlib import Path

from rich.console import Console

from jeffrey.investigation import investigate_build_log, parse_rollout_command, save_raw_evidence
from jeffrey.models import CommandResult, KubernetesEvidence
from jeffrey.reporter import save_markdown_report

ROLLOUT_COMMAND = "kubectl '--namespace=demo' rollout status deployment web-app '--timeout=150s'"


def test_namespace_is_extracted_from_rollout_command() -> None:
    assert parse_rollout_command(ROLLOUT_COMMAND)["namespace"] == "demo"


def test_deployment_is_extracted_from_rollout_command() -> None:
    assert parse_rollout_command(ROLLOUT_COMMAND)["deployment"] == "web-app"


def test_timeout_is_extracted_from_rollout_command() -> None:
    assert parse_rollout_command(ROLLOUT_COMMAND)["timeout"] == "150s"


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


def test_image_pull_backoff_refines_root_cause(tmp_path: Path, monkeypatch) -> None:
    log_path = _write_failed_rollout_log(tmp_path)
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(subprocess, "run", _fake_run_with_signal("ImagePullBackOff"))

    result = investigate_build_log(log_path)

    assert result.likely_root_cause is not None
    assert result.likely_root_cause.root_cause == (
        "Deployment rollout timed out because Kubernetes could not pull the Docker image."
    )


def test_debug_output_shows_investigation_steps(tmp_path: Path, monkeypatch) -> None:
    log_path = _write_failed_rollout_log(tmp_path)
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(subprocess, "run", _fake_run_with_signal("CrashLoopBackOff"))
    output = StringIO()
    console = Console(file=output, force_terminal=False)

    investigate_build_log(log_path, debug=True, console=console)

    rendered = output.getvalue()
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
    assert "$ kubectl get pods -n demo -l app=web-app" in rendered
    assert "$ kubectl describe deployment web-app -n demo" in rendered


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
        pods_output=CommandResult(
            command=["kubectl", "get", "pods"],
            exit_code=0,
            stdout="pods",
        ),
        events_output=CommandResult(
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

    assert (output_dir / "deployment.txt").read_text(encoding="utf-8") == "deployment details"
    assert (output_dir / "pods.txt").read_text(encoding="utf-8") == "pods"
    assert (output_dir / "events.txt").read_text(encoding="utf-8") == "events"
    assert "pod describe" in (output_dir / "pod_describe.txt").read_text(encoding="utf-8")
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
    assert result.k8s_evidence.events_output is not None
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


def _write_failed_rollout_log(tmp_path: Path) -> Path:
    log_path = tmp_path / "failed.log"
    log_path.write_text(
        "\n".join(
            [
                "[Pipeline] { (Deploy)",
                f"[2026-07-06T13:36:20.261Z] + {ROLLOUT_COMMAND}",
                "[2026-07-06T13:38:57.386Z] error: timed out waiting for the condition",
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
    if command[:4] == ["kubectl", "get", "pods", "-n"]:
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
    elif command[:3] == ["kubectl", "get", "events"]:
        stdout = signal or "Normal rollout event\n"

    return subprocess.CompletedProcess(command, 0, stdout=stdout, stderr="")
