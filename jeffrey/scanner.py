from __future__ import annotations

import re
from collections import deque
from collections.abc import Iterable
from pathlib import Path

from jeffrey.models import Finding, ScanResult, SuccessfulRollout
from jeffrey.rules import RULES, Rule

STAGE_PATTERN = re.compile(r"^\[Pipeline\]\s+\{\s+\((?P<stage>[^)]+)\)")
COMMAND_PATTERN = re.compile(r"^(?:\[[^\]]+\]\s*)?\+\s+(?P<command>.+)$")
FINISHED_PATTERN = re.compile(r"\bFinished:\s+(?P<status>[A-Z]+)\b")
SUCCESSFUL_ROLLOUT_PATTERN = re.compile(
    r'\b(?:deployment|statefulset)\s+"(?P<name>[^"]+)"\s+successfully rolled out\b',
    re.IGNORECASE,
)


def scan_build_log(path: Path, last_lines: int = 80) -> ScanResult:
    with path.open("r", encoding="utf-8", errors="replace") as build_log:
        return scan_lines(build_log, last_lines=last_lines)


def scan_lines(lines: Iterable[str], last_lines: int = 80) -> ScanResult:
    current_stage: str | None = None
    current_command: str | None = None
    build_status: str | None = None
    successful_rollouts: list[SuccessfulRollout] = []
    last_log_lines: deque[str] = deque(maxlen=max(0, last_lines))
    findings_by_rule: dict[str, Finding] = {}

    for raw_line in lines:
        line = str(raw_line).rstrip("\n")
        last_log_lines.append(line)

        finished_match = FINISHED_PATTERN.search(line)
        if finished_match:
            build_status = finished_match.group("status")

        stage_match = STAGE_PATTERN.search(line)
        if stage_match:
            current_stage = stage_match.group("stage")
            continue

        command_match = COMMAND_PATTERN.search(line)
        if command_match:
            current_command = command_match.group("command")

        rollout_match = SUCCESSFUL_ROLLOUT_PATTERN.search(line)
        if rollout_match:
            successful_rollout = SuccessfulRollout(
                name=rollout_match.group("name"),
                command=current_command,
                evidence=line,
            )
            if successful_rollout not in successful_rollouts:
                successful_rollouts.append(successful_rollout)

        for rule in RULES:
            if not rule.matches(line):
                continue

            finding = findings_by_rule.get(rule.key)
            if finding is None:
                findings_by_rule[rule.key] = _finding_from_rule(
                    rule,
                    current_stage,
                    line,
                    current_command,
                )
            else:
                _add_evidence(finding, _evidence_for_match(line, current_command))

    ranked_findings = sorted(
        findings_by_rule.values(),
        key=lambda finding: (finding.rank, _stage_sort_key(finding.stage), finding.title),
    )
    return ScanResult(
        status=_investigation_status(build_status, ranked_findings),
        findings=ranked_findings,
        last_lines=list(last_log_lines),
        build_status=build_status,
        successful_rollouts=successful_rollouts,
    )


def _finding_from_rule(
    rule: Rule,
    stage: str | None,
    line: str,
    command: str | None,
) -> Finding:
    return Finding(
        title=rule.title,
        severity=rule.severity,
        stage=stage,
        root_cause=rule.root_cause,
        evidence=_evidence_for_match(line, command),
        what_to_check_next=list(rule.what_to_check_next),
        rank=rule.rank,
    )


def _evidence_for_match(line: str, command: str | None) -> list[str]:
    evidence = []
    if command is not None:
        if "rollout status deployment" in command:
            evidence.append(f"Jenkins rollout command: {command}")
        else:
            evidence.append(f"Command: {command}")
    evidence.append(line)
    return evidence


def _add_evidence(finding: Finding, evidence_lines: list[str]) -> None:
    for evidence in evidence_lines:
        if evidence not in finding.evidence:
            finding.evidence.append(evidence)


def _stage_sort_key(stage: str | None) -> str:
    return stage or ""


def _investigation_status(build_status: str | None, findings: list[Finding]) -> str:
    if build_status == "SUCCESS":
        return "success"
    if build_status == "FAILURE" or findings:
        return "failed"
    return "unknown"
