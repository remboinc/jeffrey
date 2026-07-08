from jeffrey.scanner import scan_lines


def test_detects_crash_loop_backoff_in_deploy_stage() -> None:
    result = scan_lines(
        [
            "[Pipeline] { (Deploy)",
            "pod/my-app is in CrashLoopBackOff",
        ]
    )

    finding = result.likely_root_cause
    assert finding is not None
    assert finding.title == "Pod is crashing after deployment"
    assert finding.stage == "Deploy"
    assert finding.evidence == ["pod/my-app is in CrashLoopBackOff"]


def test_detects_image_pull_backoff() -> None:
    result = scan_lines(["Warning Failed pod ImagePullBackOff"])

    finding = result.likely_root_cause
    assert finding is not None
    assert finding.title == "Container image could not be pulled"


def test_detects_pytest_failure_in_test_stage() -> None:
    result = scan_lines(
        [
            "[Pipeline] { (Test)",
            "pytest failed with exit code 1",
        ]
    )

    finding = result.likely_root_cause
    assert finding is not None
    assert finding.title == "Pytest reported failing tests"
    assert finding.stage == "Test"


def test_returns_unknown_result_when_no_known_pattern_exists() -> None:
    result = scan_lines(["build started", "everything is confusing", "build failed"])

    assert result.findings == []
    assert result.has_findings is False
    assert result.likely_root_cause is None
    assert result.is_success is False
    assert result.status == "running"
    assert result.log_complete is False


def test_marks_log_complete_when_pipeline_finished_without_known_status() -> None:
    result = scan_lines(["build started", "[Pipeline] End of Pipeline"])

    assert result.status == "unknown"
    assert result.log_complete is True


def test_incomplete_rollout_command_does_not_create_failure() -> None:
    result = scan_lines(
        [
            "[Pipeline] { (Deploy)",
            (
                "[2026-07-06T13:36:20.261Z] + kubectl '--namespace=demo' "
                "rollout status deployment web-app '--timeout=150s'"
            ),
            'Waiting for deployment "web-app" rollout to finish...',
        ]
    )

    assert result.status == "running"
    assert result.has_findings is False


def test_detects_successful_build_status_and_rollout_steps() -> None:
    result = scan_lines(
        [
            "[Pipeline] { (Deploy)",
            (
                "[2026-07-06T16:41:07.946Z] + kubectl '--namespace=demo' "
                "rollout status deployment web-app '--timeout=150s'"
            ),
            '[2026-07-06T16:41:30.471Z] deployment "web-app" successfully rolled out',
            "Finished: SUCCESS",
        ]
    )

    assert result.findings == []
    assert result.build_status == "SUCCESS"
    assert result.is_success is True
    assert result.successful_steps == [
        (
            "Command: kubectl '--namespace=demo' rollout status deployment web-app "
            "'--timeout=150s' -> "
            '[2026-07-06T16:41:30.471Z] deployment "web-app" successfully rolled out'
        )
    ]


def test_keeps_last_n_lines_for_unknown_logs() -> None:
    result = scan_lines([f"line {index}" for index in range(10)], last_lines=3)

    assert result.last_lines == ["line 7", "line 8", "line 9"]


def test_includes_shell_command_context_for_failure() -> None:
    result = scan_lines(
        [
            "[Pipeline] { (Deploy)",
            (
                "[2026-07-06T13:36:20.261Z] + kubectl '--namespace=demo' "
                "rollout status deployment web-app '--timeout=150s'"
            ),
            "[2026-07-06T13:38:57.386Z] error: timed out waiting for the condition",
        ]
    )

    finding = result.likely_root_cause
    assert finding is not None
    assert finding.stage == "Deploy"
    assert finding.evidence == [
        (
            "Jenkins rollout command: kubectl '--namespace=demo' "
            "rollout status deployment web-app '--timeout=150s'"
        ),
        "[2026-07-06T13:38:57.386Z] error: timed out waiting for the condition",
    ]


def test_groups_repeated_evidence_instead_of_duplicating_findings() -> None:
    result = scan_lines(
        [
            "[Pipeline] { (Deploy)",
            "pod status CrashLoopBackOff",
            "pod status CrashLoopBackOff",
            "pod status CrashLoopBackOff",
        ]
    )

    assert len(result.findings) == 1
    assert result.findings[0].evidence == ["pod status CrashLoopBackOff"]
