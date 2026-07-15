from __future__ import annotations

import subprocess

from jeffrey.kubernetes import identify_related_pods, resource_forbidden, run_command
from jeffrey.models import CommandResult


def test_identifies_related_pods_from_get_pods_output() -> None:
    pods = CommandResult(
        command=["kubectl", "get", "pods"],
        exit_code=0,
        stdout=(
            "NAME READY STATUS RESTARTS AGE\n"
            "web-app-abc-123 0/1 CrashLoopBackOff 4 3m\n"
            "other-service-abc 1/1 Running 0 3m\n"
            "worker-web-app-sidecar 1/1 Running 0 3m\n"
        ),
    )

    assert identify_related_pods(pods, "web-app") == [
        "worker-web-app-sidecar",
        "web-app-abc-123",
    ]


def test_kubectl_missing_does_not_crash(monkeypatch) -> None:
    def fake_run(*args, **kwargs):
        raise FileNotFoundError("kubectl")

    monkeypatch.setattr(subprocess, "run", fake_run)

    result = run_command(["kubectl", "get", "pods"], timeout=15)

    assert result.exit_code is None
    assert result.timed_out is False
    assert "Command not found" in result.stderr


def test_kubectl_command_timeout_does_not_crash(monkeypatch) -> None:
    def fake_run(*args, **kwargs):
        raise subprocess.TimeoutExpired(cmd=args[0], timeout=15)

    monkeypatch.setattr(subprocess, "run", fake_run)

    result = run_command(["kubectl", "get", "pods"], timeout=15)

    assert result.exit_code is None
    assert result.timed_out is True
    assert "timed out" in result.stderr


def test_resource_forbidden_detects_rbac_error() -> None:
    result = CommandResult(
        command=["kubectl", "get", "deployment", "web-app"],
        exit_code=1,
        stderr=(
            'Error from server (Forbidden): deployments.apps "web-app" is forbidden: '
            'User "developer@example.com" cannot get resource "deployments"'
        ),
    )

    assert resource_forbidden(result) is True
