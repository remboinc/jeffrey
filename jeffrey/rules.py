from __future__ import annotations

import re
from dataclasses import dataclass
from re import Pattern

from jeffrey.models import Severity


@dataclass(frozen=True)
class Rule:
    key: str
    pattern: Pattern[str]
    title: str
    severity: Severity
    root_cause: str
    what_to_check_next: tuple[str, ...]
    rank: int

    def matches(self, line: str) -> bool:
        return bool(self.pattern.search(line))


RULES: tuple[Rule, ...] = (
    Rule(
        key="oom_killed",
        pattern=re.compile(r"\bOOMKilled\b", re.IGNORECASE),
        title="Container was killed because it ran out of memory",
        severity=Severity.CRITICAL,
        root_cause="A container exceeded its memory limit and was terminated by Kubernetes.",
        what_to_check_next=(
            "Check pod status and container restart count",
            "Inspect memory limits and recent memory usage",
            "Review application memory spikes or leaks",
        ),
        rank=1,
    ),
    Rule(
        key="crash_loop_backoff",
        pattern=re.compile(r"\bCrashLoopBackOff\b", re.IGNORECASE),
        title="Pod is crashing after deployment",
        severity=Severity.CRITICAL,
        root_cause="A Kubernetes pod started, crashed, and is repeatedly restarting.",
        what_to_check_next=(
            "Run kubectl logs POD_NAME -n NAMESPACE --previous",
            "Check application startup errors",
            "Check environment variables and secrets",
        ),
        rank=2,
    ),
    Rule(
        key="image_pull",
        pattern=re.compile(r"\b(?:ImagePullBackOff|ErrImagePull)\b", re.IGNORECASE),
        title="Container image could not be pulled",
        severity=Severity.HIGH,
        root_cause="Kubernetes could not download the container image required by the pod.",
        what_to_check_next=(
            "Verify the image name and tag",
            "Check registry credentials and imagePullSecrets",
            "Confirm the image exists in the registry",
        ),
        rank=3,
    ),
    Rule(
        key="container_config",
        pattern=re.compile(r"\bCreateContainerConfigError\b", re.IGNORECASE),
        title="Container configuration is invalid",
        severity=Severity.HIGH,
        root_cause=(
            "Kubernetes could not create the container because its configuration is invalid "
            "or incomplete."
        ),
        what_to_check_next=(
            "Describe the pod and inspect events",
            "Check ConfigMap and Secret references",
            "Validate environment variables, volumes, and mounts",
        ),
        rank=4,
    ),
    Rule(
        key="readiness_probe",
        pattern=re.compile(r"\bReadiness probe failed\b", re.IGNORECASE),
        title="Readiness probe is failing",
        severity=Severity.HIGH,
        root_cause=(
            "The application did not become ready according to its Kubernetes readiness probe."
        ),
        what_to_check_next=(
            "Check the readiness endpoint from inside the cluster",
            "Inspect application startup time and dependencies",
            "Review probe path, port, timeout, and initial delay",
        ),
        rank=5,
    ),
    Rule(
        key="liveness_probe",
        pattern=re.compile(r"\bLiveness probe failed\b", re.IGNORECASE),
        title="Liveness probe is failing",
        severity=Severity.HIGH,
        root_cause="Kubernetes is restarting the container because its liveness probe fails.",
        what_to_check_next=(
            "Inspect container logs around the restart time",
            "Review liveness probe timeout and failure threshold",
            "Check whether the application is deadlocking or blocking health checks",
        ),
        rank=5,
    ),
    Rule(
        key="helm_upgrade_failed",
        pattern=re.compile(r"\bUPGRADE FAILED\b", re.IGNORECASE),
        title="Helm upgrade failed",
        severity=Severity.HIGH,
        root_cause="Helm reported that the release upgrade failed.",
        what_to_check_next=(
            "Inspect the Helm error message above the failure",
            "Check rendered manifests and release history",
            "Review Kubernetes events for the affected resources",
        ),
        rank=6,
    ),
    Rule(
        key="job_wait_timeout",
        pattern=re.compile(
            r"\b(?:timed out waiting for the condition on jobs/|job\.batch/.*condition=complete)",
            re.IGNORECASE,
        ),
        title="Kubernetes Job timed out",
        severity=Severity.HIGH,
        root_cause="Kubernetes Job timed out before reaching condition=complete.",
        what_to_check_next=(
            "Inspect the Job pod logs",
            "Check Job status and backoff limit",
            "Review pod events for scheduling or runtime failures",
        ),
        rank=6,
    ),
    Rule(
        key="rollout_timeout",
        pattern=re.compile(
            r"\b(?:timed out waiting for the condition|exceeded its progress deadline)\b",
            re.IGNORECASE,
        ),
        title="Deployment rollout timed out",
        severity=Severity.HIGH,
        root_cause="Deployment rollout timed out",
        what_to_check_next=(
            "Describe the deployment and pods",
            "Check pod events for scheduling, image, or probe failures",
            "Inspect logs from newly created pods",
        ),
        rank=6,
    ),
    Rule(
        key="pytest_failed",
        pattern=re.compile(r"\bpytest failed\b", re.IGNORECASE),
        title="Pytest reported failing tests",
        severity=Severity.MEDIUM,
        root_cause="The test suite failed during the CI run.",
        what_to_check_next=(
            "Open the first failing pytest traceback",
            "Run the failing test locally",
            "Check recent changes touching the failed behavior",
        ),
        rank=7,
    ),
    Rule(
        key="assertion_error",
        pattern=re.compile(r"\bAssertionError\b", re.IGNORECASE),
        title="A test assertion failed",
        severity=Severity.MEDIUM,
        root_cause="A test or runtime assertion failed.",
        what_to_check_next=(
            "Inspect the assertion traceback",
            "Compare expected and actual values",
            "Run the affected test with verbose output",
        ),
        rank=7,
    ),
    Rule(
        key="module_not_found",
        pattern=re.compile(r"\bModuleNotFoundError\b", re.IGNORECASE),
        title="Python module is missing",
        severity=Severity.MEDIUM,
        root_cause="Python could not import a required module.",
        what_to_check_next=(
            "Check dependency installation in the CI environment",
            "Verify package names and optional extras",
            "Confirm the virtual environment is activated",
        ),
        rank=8,
    ),
    Rule(
        key="permission_denied",
        pattern=re.compile(r"\bpermission denied\b", re.IGNORECASE),
        title="Permission denied",
        severity=Severity.MEDIUM,
        root_cause="The build tried to access or execute something without sufficient permissions.",
        what_to_check_next=(
            "Check file permissions and ownership",
            "Verify executable bits on scripts",
            "Review CI runner user permissions",
        ),
        rank=8,
    ),
    Rule(
        key="no_space",
        pattern=re.compile(r"\bno space left on device\b", re.IGNORECASE),
        title="Build agent ran out of disk space",
        severity=Severity.HIGH,
        root_cause="The CI worker or target host has no free disk space left.",
        what_to_check_next=(
            "Check disk usage on the CI worker",
            "Remove stale build artifacts or Docker layers",
            "Increase workspace or node disk capacity",
        ),
        rank=8,
    ),
    Rule(
        key="connection_refused",
        pattern=re.compile(r"\bconnection refused\b", re.IGNORECASE),
        title="Connection was refused",
        severity=Severity.MEDIUM,
        root_cause="A service connection failed because the remote endpoint refused it.",
        what_to_check_next=(
            "Verify the target service is running",
            "Check host, port, and network policy",
            "Inspect service startup order and readiness",
        ),
        rank=8,
    ),
)
