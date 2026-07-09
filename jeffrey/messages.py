REPORT_TITLE = "Jeffrey investigation report"
UNKNOWN_ROOT_CAUSE = "Jeffrey could not determine the root cause yet"
INCOMPLETE_LOG = "Jenkins log appears incomplete or the build is still running."
INCOMPLETE_LOG_ANALYZED = "Jeffrey analyzed the lines available so far."
LAST_LOG_LINES_TITLE = "Last log lines"
BUILD_SUCCESS = "Build finished successfully."
NO_FAILURE_TO_INVESTIGATE = "There is no failure root cause to investigate."

SECTION_LIKELY_ROOT_CAUSE = "Likely root cause"
SECTION_STAGE = "Stage"
SECTION_DEPLOYMENT = "Deployment"
SECTION_JOB = "Job"
SECTION_NAMESPACE = "Namespace"
SECTION_EVIDENCE = "Evidence"
SECTION_SUCCESSFUL_ROLLOUT_STEPS = "Successful rollout steps"
SECTION_COLLECTED_EVIDENCE = "Collected evidence"
SECTION_INVESTIGATION_SUMMARY = "Investigation summary"
SECTION_BUILD = "Build"
SECTION_PODS_INVESTIGATED = "Pods investigated"
SECTION_SELECTOR = "Selector"
SECTION_CORRELATED_EVENTS_FOUND = "Correlated events found"
SECTION_UNRELATED_NAMESPACE_EVENTS_IGNORED = "Unrelated namespace events ignored"
SECTION_EVENTS_COLLECTED = "Events collected"
SECTION_PREVIOUS_LOGS = "Previous logs"
SECTION_DURATION = "Duration"
SECTION_RAW_EVIDENCE = "Raw evidence saved to"
SECTION_KUBERNETES_SIGNAL = "Kubernetes signal"
SECTION_RELEVANT_LOG_EXCERPTS = "Relevant log excerpts"
SECTION_MORE_LOG_EXCERPTS = "More log excerpts saved to"
SECTION_JEFFREY_CONCLUSION = "Jeffrey conclusion"
SECTION_MANUAL_FOLLOW_UP = "Manual follow-up"
SECTION_WARNING = "Warning"
SECTION_ALSO_DETECTED = "Also detected"
SECTION_ALL_DETECTED_FINDINGS = "All detected findings"

UNKNOWN_VALUE = "Unknown"
YES = "Yes"
NO = "No"
NO_ACTION_REQUIRED = "No action required."
BUILD_FINISHED_SUCCESSFULLY_EVIDENCE = "Build finished successfully."
NONE_VALUE = "None"
NOT_AVAILABLE = "Not available"

ROOT_CAUSE_ROLLOUT_TIMEOUT = "Deployment rollout timed out"
ROOT_CAUSE_JOB_TIMEOUT = "Kubernetes Job timed out before reaching condition=complete."
ROOT_CAUSE_CRASH_LOOP = (
    "Deployment rollout timed out because one or more pods are crashing after startup."
)
ROOT_CAUSE_IMAGE_PULL = (
    "Deployment rollout timed out because Kubernetes could not pull the Docker image."
)
ROOT_CAUSE_OOM_KILLED = (
    "Deployment rollout timed out because a container was killed due to memory limits."
)
ROOT_CAUSE_CONTAINER_CONFIG = (
    "Deployment rollout timed out because Kubernetes could not create the "
    "container configuration."
)
ROOT_CAUSE_READINESS_FAILED = (
    "Deployment rollout timed out because pods did not pass readiness checks."
)
ROOT_CAUSE_DEPENDENCY_CONNECTION_REFUSED = (
    "Deployment rollout timed out because the application or one of its dependencies "
    "refused connections."
)
ROOT_CAUSE_MISSING_PYTHON_MODULE = (
    "Deployment rollout timed out because the application failed to start due to "
    "a missing Python module."
)
ROOT_CAUSE_IMPORT_ERROR = (
    "Deployment rollout timed out because the application failed to start due to "
    "a Python import error."
)
ROOT_CAUSE_PERMISSION_ERROR = (
    "Deployment rollout timed out because the application hit a permission error."
)
ROOT_CAUSE_READINESS_UNRELIABLE = (
    "Deployment rollout timed out because the application did not reliably respond to "
    "readiness checks."
)
ROOT_CAUSE_READINESS_PORT_REFUSED = (
    "Deployment rollout timed out because the application was not accepting connections "
    "on the readiness port."
)
ROOT_CAUSE_READINESS_TIMED_OUT = (
    "Deployment rollout timed out because readiness checks timed out before the "
    "application responded."
)
ROOT_CAUSE_PANIC_WITH_READINESS = (
    "Deployment rollout timed out because the application did not reliably respond to "
    "readiness checks and pod logs show panic recovery events."
)
ROOT_CAUSE_PANIC = (
    "Deployment rollout timed out because pod logs show application panic recovery events."
)
ROOT_CAUSE_APP_LOGS_CONNECTION_REFUSED = (
    "Deployment rollout timed out because application logs show refused connections."
)

NEXT_STEPS_STARTUP = (
    "Inspect previous container logs",
    "Check application startup errors",
    "Check environment variables and secrets",
)
NEXT_STEPS_IMAGE_PULL = (
    "Check image tag",
    "Check registry credentials",
    "Check whether the image exists",
)
NEXT_STEPS_MEMORY = (
    "Check memory limits",
    "Check recent memory usage",
    "Compare with the previous successful deployment",
)
NEXT_STEPS_CONTAINER_CONFIG = (
    "Check ConfigMap references",
    "Check Secret references",
    "Check environment variable definitions",
)
NEXT_STEPS_READINESS = (
    "Check readiness probe path and port",
    "Check application startup time",
    "Check pod logs and service dependencies",
)
NEXT_STEPS_CONNECTION = (
    "Check dependent services",
    "Check ports and service names",
    "Check application startup logs",
)
NEXT_STEPS_PYTHON_IMPORT = (
    "Check requirements files",
    "Check Docker image build",
    "Check import path and startup command",
)
NEXT_STEPS_PERMISSION = (
    "Check file permissions",
    "Check container user",
    "Check mounted volumes",
)


def no_pods_matched(deployment: str) -> str:
    return f"No pods were matched for deployment {deployment}, so pod logs could not be analyzed."


def application_logs_unavailable() -> str:
    return "Application logs could not be collected."


def no_startup_errors() -> str:
    return "No known startup errors were found in the application logs."


def no_suspicious_log_lines(pod_name: str) -> str:
    return (
        f"Logs were collected for pod/{pod_name}, but no suspicious application log "
        "lines were detected."
    )


def previous_logs_not_available() -> str:
    return "previous logs were not available"


def no_correlated_warning_events() -> str:
    return "no correlated warning events found"


def log_unavailable(source: str, pod_name: str) -> str:
    label = "Current" if source == "logs" else "Previous"
    return f"{label} logs were not available for pod/{pod_name}."


def jenkins_rollout_timed_out(timeout: str | None) -> str:
    if timeout:
        return f"Jenkins rollout command timed out after {timeout}"
    return "Jenkins rollout command timed out"


def jenkins_job_timed_out(job: str, condition: str | None, timeout: str | None) -> str:
    waited_for = f"condition={condition}" if condition else "the requested condition"
    if timeout:
        return f"Jenkins command waited for job.batch/{job} {waited_for} for {timeout}"
    return f"Jenkins command waited for job.batch/{job} {waited_for}"


def jenkins_job_error(line: str) -> str:
    return f"Jenkins error: {line}"


def job_pod_status(pod_name: str, status: str) -> str:
    return f"Job pod {pod_name} status: {status}"


def job_pod_logs_contain(message: str) -> str:
    return f"Job pod logs contain: {message}"


def job_did_not_complete() -> str:
    return "Job did not reach Complete condition"


def pods_matched(count: int) -> str:
    return f"Pods matched: {count}"


def pod_status(status: str) -> str:
    return f"Pod status: {status}"


def job_pod_logs_not_analyzed(job: str) -> str:
    return f"No pods were matched for Job {job}, so Job pod logs could not be analyzed."


def job_conclusion_timeout() -> str:
    return "Jenkins waited for the Kubernetes Job to complete, but it timed out."


def job_conclusion_logs_checked() -> str:
    return "Jeffrey found the Job pod and analyzed its logs."


def current_job_state_warning(failed_at: str) -> str:
    return (
        "Kubernetes is being inspected now, but the Jenkins failure happened at "
        f"{failed_at}. Current Job/Pod state may differ from the failed build state."
    )


def no_correlated_kubernetes_failure() -> str:
    return "No correlated Kubernetes pod failure was found in current cluster state."


def fallback_pod_matching_used() -> str:
    return "Pod selector lookup failed; fallback pod name matching was used"


def no_deeper_kubernetes_cause() -> str:
    return "No deeper Kubernetes cause was detected"


def kubernetes_readiness_failed(pod_name: str) -> str:
    return f"Kubernetes readiness probe failed for pod/{pod_name}"


def kubernetes_signal(signal: str) -> str:
    return f"Kubernetes signal: {signal}"


def readiness_endpoint(path: str, port: int | None, outcome: str) -> str:
    if port is None:
        return f"Readiness endpoint {path} {outcome}"
    return f"Readiness endpoint {path} on port {port} {outcome}"


def current_state_warning(failed_at: str) -> str:
    return (
        "Kubernetes is being inspected now, but the Jenkins failure happened at "
        f"{failed_at}. Current cluster state may differ from the failed build state."
    )


def root_cause_conclusion(root_cause: str) -> str:
    return root_cause.rstrip(".") + "."


def readiness_conclusion() -> str:
    return "The pod did not become ready during rollout."


def missing_module_conclusion() -> str:
    return "The application failed to start because a Python module was missing."


def crashing_conclusion() -> str:
    return "One or more pods were crashing after startup."


def checked_kubernetes_events_and_describe() -> str:
    return "Jeffrey checked Kubernetes events and pod describe output."


def checked_kubernetes_evidence() -> str:
    return "Jeffrey checked Kubernetes deployment, pod and event evidence."


def cluster_state_may_differ() -> str:
    return "Current cluster state may differ from the failed build state."


def readiness_endpoint_unreliable() -> str:
    return (
        "Kubernetes could reach the pod IP, but the readiness endpoint did not "
        "respond reliably."
    )


def readiness_endpoint_refused() -> str:
    return "The readiness endpoint refused connections."


def readiness_endpoint_timed_out() -> str:
    return "The readiness endpoint timed out before responding."


def correlated_readiness_failure() -> str:
    return "Kubernetes reported a correlated pod readiness failure."


def no_application_startup_errors() -> str:
    return "No known application startup errors were found in collected logs."


def application_logs_could_not_be_collected() -> str:
    return "Application logs could not be collected."


def application_logs_contained_errors() -> str:
    return "Application logs contained known error patterns."


def previous_logs_unavailable_conclusion() -> str:
    return "Previous logs were not available."


def run_with_kubectl_access() -> str:
    return "Run Jeffrey from a machine with kubectl access."


def check_deployment_selector() -> str:
    return "Check the deployment selector."


def check_pod_logs_manually() -> str:
    return "Check pod logs manually because Kubernetes did not return logs."
