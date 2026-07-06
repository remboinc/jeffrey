from jeffrey.scanner import scan_lines


def test_oom_killed_ranks_above_rollout_timeout() -> None:
    result = scan_lines(
        [
            "[Pipeline] { (Deploy)",
            "deployment exceeded its progress deadline",
            "container terminated with reason OOMKilled",
        ]
    )

    assert [finding.title for finding in result.findings] == [
        "Container was killed because it ran out of memory",
        "Deployment rollout timed out",
    ]
