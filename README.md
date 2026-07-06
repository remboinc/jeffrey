# Jeffrey

Jeffrey is a Python CLI tool that investigates failed CI/CD builds and explains the likely root cause in human-readable form.

The MVP scans a local Jenkins build log. When the Jenkins log shows a Kubernetes deployment rollout failure, Jeffrey automatically collects Kubernetes evidence with `kubectl` and correlates it with the Jenkins symptom.

Jeffrey does not call AI APIs and does not require Jenkins API access.

## Installation

With `pipx`:

```bash
pipx install .
```

From a Git repository:

```bash
pipx install git+https://github.com/OWNER/REPO.git
```

For local development:

```bash
python3.12 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

## Usage

```bash
jeffrey scan --build-log ./jenkins.log
jeffrey scan --build-log ./jenkins.log --no-k8s
jeffrey scan --build-log ./jenkins.log --show-commands
jeffrey scan --build-log ./jenkins.log --verbose
jeffrey scan --build-log ./jenkins.log --debug
jeffrey scan --build-log ./jenkins.log --save-report report.md
```

## Default Behavior

By default, Jeffrey:

- parses the Jenkins log
- detects successful builds and successful rollouts
- detects failed rollout timeouts
- verifies the local Kubernetes environment when a rollout failure is found
- extracts namespace, deployment name, and rollout timeout from the Jenkins `kubectl rollout status` command
- automatically runs Kubernetes investigation only when the Jenkins log indicates a deployment-related failure
- stores raw Kubernetes evidence under `.jeffrey/`

For a rollout timeout like:

```text
kubectl '--namespace=demo' rollout status deployment web-app '--timeout=150s'
error: timed out waiting for the condition
```

Jeffrey extracts:

- namespace: `demo`
- deployment: `web-app`
- timeout: `150s`

Then it runs deployment-scoped collection:

```bash
kubectl get deployment web-app -n demo -o json
kubectl describe deployment web-app -n demo
kubectl get pods -n demo -l app=web-app -o json
```

Jeffrey uses the deployment selector from JSON to find pods. If related pods are found,
Jeffrey collects pod descriptions, pod-specific events, and current/previous logs for up to
3 pods.

Jeffrey first tries pod discovery with:

```bash
kubectl get pods -n demo -l app=web-app
```

If selector lookup fails, it falls back to name matching and marks that fallback in the report.

```bash
kubectl get pods -n demo
```

Candidate pods are ranked and `Completed` pods are ignored.

## Kubernetes Options

Disable automatic Kubernetes investigation:

```bash
jeffrey scan --build-log ./jenkins.log --no-k8s
```

Print the `kubectl` commands Jeffrey runs:

```bash
jeffrey scan --build-log ./jenkins.log --show-commands
```

Print the concise report plus a compact investigation summary:

```bash
jeffrey scan --build-log ./jenkins.log --verbose
```

Print detailed debug output:

```bash
jeffrey scan --build-log ./jenkins.log --debug
```

Output modes:

- default: concise report
- `--verbose`: concise report plus compact summary
- `--debug`: full internal investigation trace
- `--show-commands`: executed shell commands only

Save a Markdown report:

```bash
jeffrey scan --build-log ./jenkins.log --save-report report.md
```

Raw evidence is saved automatically in `.jeffrey/`:

- `deployment.json`
- `deployment_describe.txt`
- `pods.json`
- `pods.txt`
- `pod_<pod_name>_describe.txt`
- `pod_<pod_name>_events.txt`
- `pod_<pod_name>_logs.txt`
- `pod_<pod_name>_previous_logs.txt`
- `namespace_events.txt` as uncorrelated raw context
- `commands.txt`

## Supported Patterns

- `CrashLoopBackOff`
- `ImagePullBackOff`
- `ErrImagePull`
- `OOMKilled`
- `CreateContainerConfigError`
- `Readiness probe failed`
- `Liveness probe failed`
- `UPGRADE FAILED`
- `timed out waiting for the condition`
- `exceeded its progress deadline`
- `pytest failed`
- `AssertionError`
- `ModuleNotFoundError`
- `permission denied`
- `no space left on device`
- `connection refused`

Jeffrey detects Jenkins stages from log lines like:

```text
[Pipeline] { (Deploy)
[Pipeline] { (Test)
[Pipeline] { (Build)
```

## MVP Limitations

- Reads only local log files.
- Uses deterministic pattern matching only.
- Does not call AI APIs.
- Does not connect to Jenkins.
- Kubernetes investigation requires `kubectl` and a working kubeconfig.
- If Kubernetes is unavailable, Jeffrey still reports the Jenkins-level diagnosis.
- Pod matching first tries `app=<deployment>`, then falls back to prefix/contains matching.
- Kubernetes log collection is limited to 3 matching pods.
- Kubernetes command timeout defaults to 15 seconds.
- Root-cause explanations are based on known log patterns and may need human verification.

## Future Roadmap

- Jenkins API adapter
- GitHub Actions adapter
- GitLab CI adapter
- More accurate Kubernetes ownership-based pod matching
- Markdown report export

## Development

```bash
pytest
ruff check .
```
