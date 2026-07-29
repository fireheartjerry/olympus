# VPS Development Migration Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make `/home/ubuntu/olympus` the verified Olympus development workspace and connect Codex Desktop to it over SSH for inline remote development.

**Architecture:** GitHub remains the canonical Git remote. The verified local `main` is pushed, cloned by the non-root `ubuntu` account, and recreated entirely from tracked files and immutable tool versions; no local secret, cache, or generated state is copied. After repository verification, the official Codex standalone CLI is installed and authenticated on the VPS so Codex Desktop can start its remote app server through the existing `neurips-vps` SSH alias.

**Tech Stack:** Git/GitHub, OpenSSH, uv 0.11.19, CPython 3.13.13, Ruff, mypy, pytest, Helm 3.17.3, kubeconform 0.8.0, Codex CLI and Codex Desktop remote connections.

---

### Task 1: Publish the Approved Repository State

**Files:**
- Verify: local Git worktree
- Verify: `origin/main`

- [ ] **Step 1: Confirm the local source is clean and identify the approved commit**

Run:

```powershell
git status --short --branch
git rev-parse HEAD
```

Expected: no changed files and `HEAD` resolves to the migration-plan commit.

- [ ] **Step 2: Push `main` to the canonical GitHub remote**

Run:

```powershell
git push origin main
```

Expected: `main -> main` succeeds without a force push.

- [ ] **Step 3: Prove local and GitHub commits are identical**

Run:

```powershell
$localCommit = git rev-parse HEAD
$remoteCommit = (git ls-remote origin refs/heads/main).Split()[0]
if ($localCommit -ne $remoteCommit) { throw "origin/main does not match local HEAD." }
```

Expected: exit code 0.

### Task 2: Create the VPS Working Checkout

**Files:**
- Create: `/home/ubuntu/olympus/`

- [ ] **Step 1: Reconfirm the destination is safe**

Run:

```powershell
ssh -o BatchMode=yes neurips-vps 'test ! -e /home/ubuntu/olympus'
```

Expected: exit code 0. Stop if the path exists unexpectedly.

- [ ] **Step 2: Clone the canonical repository as the non-root user**

Run:

```powershell
ssh neurips-vps 'git clone --branch main --single-branch https://github.com/fireheartjerry/olympus.git /home/ubuntu/olympus'
```

Expected: clone completes without credentials or root access.

- [ ] **Step 3: Prove checkout identity and cleanliness**

Run:

```powershell
$localCommit = git rev-parse HEAD
$vpsCommit = ssh neurips-vps 'git -C /home/ubuntu/olympus rev-parse HEAD'
if ($localCommit -ne $vpsCommit.Trim()) { throw "VPS HEAD does not match local HEAD." }
ssh neurips-vps 'test -z "$(git -C /home/ubuntu/olympus status --short)"'
```

Expected: commit IDs match and the VPS worktree is clean.

### Task 3: Install the Pinned Python Toolchain

**Files:**
- Create: `/home/ubuntu/.local/bin/uv`
- Create: `/home/ubuntu/.local/share/uv/python/`
- Create: `/home/ubuntu/olympus/.venv/`

- [ ] **Step 1: Download and verify uv 0.11.19**

Run:

```powershell
ssh neurips-vps 'set -eu
tool_dir="$HOME/.local/bin"
temp_dir="$(mktemp -d)"
trap "rm -rf -- \"$temp_dir\"" EXIT
archive="$temp_dir/uv.tar.gz"
checksum="$temp_dir/uv.tar.gz.sha256"
curl --fail --location --retry 3 --silent --show-error \
  https://github.com/astral-sh/uv/releases/download/0.11.19/uv-x86_64-unknown-linux-gnu.tar.gz \
  --output "$archive"
curl --fail --location --retry 3 --silent --show-error \
  https://github.com/astral-sh/uv/releases/download/0.11.19/uv-x86_64-unknown-linux-gnu.tar.gz.sha256 \
  --output "$checksum"
expected="$(cut -d " " -f 1 "$checksum")"
actual="$(sha256sum "$archive" | cut -d " " -f 1)"
test "$actual" = "$expected"
tar --extract --gzip --file "$archive" --directory "$temp_dir"
install --directory --mode=0755 "$tool_dir"
install --mode=0755 "$temp_dir/uv-x86_64-unknown-linux-gnu/uv" "$tool_dir/uv"
install --mode=0755 "$temp_dir/uv-x86_64-unknown-linux-gnu/uvx" "$tool_dir/uvx"
"$tool_dir/uv" --version'
```

Expected: `uv 0.11.19`.

- [ ] **Step 2: Install CPython 3.13.13**

Run:

```powershell
ssh neurips-vps '$HOME/.local/bin/uv python install 3.13.13'
```

Expected: uv reports CPython 3.13.13 installed under the `ubuntu` account.

- [ ] **Step 3: Recreate the locked development environment**

Run:

```powershell
ssh neurips-vps 'cd /home/ubuntu/olympus && $HOME/.local/bin/uv lock --check && $HOME/.local/bin/uv sync --locked --all-groups'
```

Expected: 39 locked packages resolve and the project `.venv` is created.

### Task 4: Install the Pinned Kubernetes Validation Tools

**Files:**
- Create: `/home/ubuntu/.local/bin/helm`
- Create: `/home/ubuntu/.local/bin/kubeconform`

- [ ] **Step 1: Install checksum-verified Helm 3.17.3**

Run:

```powershell
ssh neurips-vps 'set -eu
temp_dir="$(mktemp -d)"
trap "rm -rf -- \"$temp_dir\"" EXIT
archive="$temp_dir/helm.tar.gz"
curl --fail --location --retry 3 --silent --show-error \
  https://get.helm.sh/helm-v3.17.3-linux-amd64.tar.gz \
  --output "$archive"
echo "ee88b3c851ae6466a3de507f7be73fe94d54cbf2987cbaa3d1a3832ea331f2cd  $archive" | sha256sum --check --status
tar --extract --gzip --file "$archive" --directory "$temp_dir" linux-amd64/helm
install --mode=0755 "$temp_dir/linux-amd64/helm" "$HOME/.local/bin/helm"
"$HOME/.local/bin/helm" version --short'
```

Expected: Helm reports `v3.17.3`.

- [ ] **Step 2: Install checksum-verified kubeconform 0.8.0**

Run:

```powershell
ssh neurips-vps 'set -eu
temp_dir="$(mktemp -d)"
trap "rm -rf -- \"$temp_dir\"" EXIT
archive="$temp_dir/kubeconform.tar.gz"
curl --fail --location --retry 3 --silent --show-error \
  https://github.com/yannh/kubeconform/releases/download/v0.8.0/kubeconform-linux-amd64.tar.gz \
  --output "$archive"
echo "9bc2bffbf71f261128533edaf912153948b7ff238f9a531ae6d34466ec287883  $archive" | sha256sum --check --status
tar --extract --gzip --file "$archive" --directory "$temp_dir" kubeconform
install --mode=0755 "$temp_dir/kubeconform" "$HOME/.local/bin/kubeconform"
"$HOME/.local/bin/kubeconform" -v'
```

Expected: kubeconform reports `v0.8.0`.

### Task 5: Verify the Complete Repository on the VPS

**Files:**
- Create ignored artifacts: `/home/ubuntu/olympus/outputs/vps-migration-verification/`

- [ ] **Step 1: Build and inspect release artifacts**

Run:

```powershell
ssh neurips-vps 'set -eu
cd /home/ubuntu/olympus
UV="$HOME/.local/bin/uv"
"$UV" build --out-dir outputs/vps-migration-verification
"$UV" run python -m olympus.build.verify_distribution \
  outputs/vps-migration-verification/*.whl \
  outputs/vps-migration-verification/*.tar.gz'
```

Expected: wheel and sdist build, and distribution verification exits 0.

- [ ] **Step 2: Run formatting, lint, typing, and tests**

Run:

```powershell
ssh neurips-vps 'set -eu
cd /home/ubuntu/olympus
UV="$HOME/.local/bin/uv"
"$UV" run ruff format --check src tests
"$UV" run ruff check src tests
"$UV" run mypy
"$UV" run pytest -W error'
```

Expected: Ruff passes, mypy reports no issues, and all 97 tests pass.

- [ ] **Step 3: Run the strict Helm guardrail verifier**

Run:

```powershell
ssh neurips-vps 'set -eu
cd /home/ubuntu/olympus
pwsh -NoLogo -NoProfile \
  -File deploy/helm/olympus-foundation/tests/verify.ps1 \
  -HelmPath "$HOME/.local/bin/helm" \
  -KubeconformPath "$HOME/.local/bin/kubeconform" \
  -KubernetesVersion "1.36.1" \
  -SchemaLocation "https://raw.githubusercontent.com/yannh/kubernetes-json-schema/05eeed51991935dd1f47cd3b3682de4e8af233f3/{{.NormalizedKubernetesVersion}}-standalone-strict/{{.ResourceKind}}.json"'
```

Expected: 8 resources validate, all override-rejection cases pass, and the rendered guardrails match `CapacityPlan`.

- [ ] **Step 4: Confirm final Git state**

Run:

```powershell
ssh neurips-vps 'cd /home/ubuntu/olympus && git diff --check && git status --short --branch'
```

Expected: `main...origin/main` with no changed or untracked files.

### Task 6: Install and Authenticate Codex on the VPS

**Files:**
- Create: `/home/ubuntu/.local/bin/codex`
- Create sensitive runtime state: `/home/ubuntu/.codex/` through the supported login flow

- [ ] **Step 1: Install Codex with the official standalone installer**

Run:

```powershell
ssh neurips-vps 'set -eu
installer="$(mktemp)"
trap "rm -f -- \"$installer\"" EXIT
curl --fail --location --retry 3 --silent --show-error \
  https://chatgpt.com/codex/install.sh \
  --output "$installer"
CODEX_NON_INTERACTIVE=1 sh "$installer"
"$HOME/.local/bin/codex" --version'
```

Expected: the official installer succeeds and `codex --version` prints the installed version.

- [ ] **Step 2: Confirm the login shell can find Codex**

Run:

```powershell
ssh neurips-vps 'command -v codex && codex --version'
```

Expected: `codex` resolves from the `ubuntu` login shell.

- [ ] **Step 3: Authenticate through device code**

Run interactively:

```powershell
ssh -t neurips-vps 'codex login --device-auth'
```

Expected: Jerry completes the one-time browser code flow; no credential file is copied from the local computer.

- [ ] **Step 4: Verify authenticated CLI access**

Run:

```powershell
ssh neurips-vps 'codex login status'
```

Expected: exit code 0 and an authenticated ChatGPT/Codex session.

### Task 7: Connect Codex Desktop to the VPS Workspace

**Files:**
- Reuse: `C:\Users\fireh\.ssh\config`
- Register remote project: `/home/ubuntu/olympus`

- [ ] **Step 1: Confirm the existing SSH alias meets Codex requirements**

Run:

```powershell
ssh -o BatchMode=yes neurips-vps 'test -d /home/ubuntu/olympus && command -v codex'
```

Expected: exit code 0.

- [ ] **Step 2: Add the SSH host in Codex Desktop**

Open **Settings > Connections**, add or enable the discovered `neurips-vps` alias, and select `/home/ubuntu/olympus` as the remote project.

Expected: Codex Desktop lists the Olympus project on `neurips-vps`.

- [ ] **Step 3: Hand off development to the VPS**

Use the task footer's run-location control to select `neurips-vps` and the matching Olympus project.

Expected: subsequent shell commands and file changes for the task execute against `/home/ubuntu/olympus`.

- [ ] **Step 4: Prove remote execution**

Run in the handed-off task:

```bash
pwd
git rev-parse HEAD
hostname
```

Expected: `/home/ubuntu/olympus`, the canonical GitHub commit, and the VPS hostname.
