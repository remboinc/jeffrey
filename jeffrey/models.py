from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel, Field


class Severity(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Finding(BaseModel):
    title: str
    severity: Severity
    stage: str | None = None
    root_cause: str
    evidence: list[str] = Field(default_factory=list)
    what_to_check_next: list[str] = Field(default_factory=list)
    metadata: dict[str, str] = Field(default_factory=dict)
    rank: int = 100


class SuccessfulRollout(BaseModel):
    name: str
    command: str | None = None
    evidence: str


class JenkinsRolloutContext(BaseModel):
    namespace: str
    deployment: str
    timeout: str | None = None
    command: str

    def __getitem__(self, key: str) -> str:
        value = getattr(self, key)
        if value is None:
            raise KeyError(key)
        return value

    def to_metadata(self) -> dict[str, str]:
        metadata = {
            "namespace": self.namespace,
            "deployment": self.deployment,
            "jenkins_rollout_command": self.command,
        }
        if self.timeout is not None:
            metadata["timeout"] = self.timeout
        return metadata


class CommandResult(BaseModel):
    command: list[str]
    exit_code: int | None = None
    stdout: str = ""
    stderr: str = ""
    timed_out: bool = False

    @property
    def command_text(self) -> str:
        return " ".join(self.command)

    @property
    def succeeded(self) -> bool:
        return self.exit_code == 0 and not self.timed_out


class EnvironmentCheck(BaseModel):
    kubectl_found: bool = False
    kubeconfig_loaded: bool = False
    current_context: str | None = None
    current_namespace: str | None = None
    messages: list[str] = Field(default_factory=list)
    commands: list[CommandResult] = Field(default_factory=list)


class KubernetesEvidence(BaseModel):
    namespace: str
    deployment: str
    environment: EnvironmentCheck | None = None
    deployment_json: CommandResult | None = None
    deployment_description: CommandResult | None = None
    selector: dict[str, str] = Field(default_factory=dict)
    selector_text: str | None = None
    selector_lookup_failed: bool = False
    fallback_pod_matching_used: bool = False
    replica_sets: list[str] = Field(default_factory=list)
    labeled_pods_output: CommandResult | None = None
    pods_json: CommandResult | None = None
    pods_output: CommandResult | None = None
    namespace_events_output: CommandResult | None = None
    events_output: CommandResult | None = None
    selected_pods: list[str] = Field(default_factory=list)
    pod_descriptions: dict[str, CommandResult] = Field(default_factory=dict)
    pod_events: dict[str, CommandResult] = Field(default_factory=dict)
    pod_logs: dict[str, CommandResult] = Field(default_factory=dict)
    pod_previous_logs: dict[str, CommandResult] = Field(default_factory=dict)
    command_errors: list[CommandResult] = Field(default_factory=list)
    executed_commands: list[CommandResult] = Field(default_factory=list)
    correlated_events_found: int = 0
    unrelated_namespace_events_ignored: int = 0

    @property
    def pods_checked(self) -> int:
        return len(self.pod_descriptions)

    @property
    def previous_logs_checked(self) -> bool:
        return bool(self.pod_previous_logs)


class BuildInvestigation(BaseModel):
    status: str = "unknown"
    findings: list[Finding] = Field(default_factory=list)
    build_status: str | None = None
    successful_rollouts: list[SuccessfulRollout] = Field(default_factory=list)
    rollout_context: JenkinsRolloutContext | None = None
    k8s_evidence: KubernetesEvidence | None = None
    last_lines: list[str] = Field(default_factory=list)
    duration_seconds: float | None = None
    raw_evidence_dir: str | None = None

    @property
    def has_findings(self) -> bool:
        return bool(self.findings)

    @property
    def is_success(self) -> bool:
        return self.build_status == "SUCCESS"

    @property
    def likely_root_cause(self) -> Finding | None:
        if not self.findings:
            return None
        return self.findings[0]

    @property
    def successful_steps(self) -> list[str]:
        steps = []
        for rollout in self.successful_rollouts:
            if rollout.command is None:
                steps.append(rollout.evidence)
            else:
                steps.append(f"Command: {rollout.command} -> {rollout.evidence}")
        return steps


ScanResult = BuildInvestigation
