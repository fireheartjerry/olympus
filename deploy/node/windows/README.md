# Olympus Windows Node Agent

Installs the Olympus execution-node agent as a Scheduled Task on a Windows
workstation that has joined the Tailscale tailnet. The agent dials OUT to the
control plane over a private WebSocket; **no inbound firewall port is opened
and no listening socket is created**, and the node's Ed25519 private key is
generated on the machine itself and never leaves it.

## Prerequisites

- Windows 10/11, PowerShell 5.1+.
- [Python 3.13](https://www.python.org/downloads/) installed and either on
  `PATH` (as `py -3.13` or `python3.13`), managed by `uv`, or passed via
  `-PythonExe`. The installer validates each executable and can use
  `uv python find --system 3.13`; it will not install Python for you.
- The machine has joined tailnet `tail70f263.ts.net` (Tailscale) and can
  resolve/reach `vps-41e741fc.tail70f263.ts.net`.
- A single-use enrollment token issued by the control plane operator.

## 1. Build the wheel on the VPS

From the Olympus repo root on the control plane host:

```bash
uv build
```

This produces `dist/olympus-<version>-py3-none-any.whl`.

## 2. Copy the wheel and this deploy folder to the Windows machine

Copy `dist/olympus-<version>-py3-none-any.whl` and the contents of
`deploy/node/windows/` (the installer script and `requirements-node.txt`) to
the target machine, e.g. `C:\temp\olympus-node\`.

## 3. Enroll and install

From an elevated PowerShell prompt (elevation is required because the default
`-InstallRoot` is under `ProgramData`):

```powershell
.\Install-OlympusNode.ps1 `
  -ControlPlaneUrl "https://vps-41e741fc.tail70f263.ts.net" `
  -EnrollmentToken (Read-Host -AsSecureString "Enrollment token") `
  -NodeName "jerry-windows" `
  -PackagePath "C:\temp\olympus-node\olympus-0.1.0-py3-none-any.whl"
```

Running the script again is safe: it will not re-enroll a node that already
has a valid config, will not duplicate the scheduled task, and will reinstall
dependencies idempotently. Pass `-Force` to re-enroll (e.g. after a config was
deleted or a key needs rotating).

If you install outside of `ProgramData` (e.g. `-InstallRoot "$env:LOCALAPPDATA\Olympus\node"`),
elevation is not required and the task runs as your own user account.

### SYSTEM-scoped alternative

If `-InstallRoot` is under `ProgramData`, this script always registers the
scheduled task as the invoking user (`RunLevel Limited`, run-whether-logged-on
kept `False`) — it does **not** silently switch to a SYSTEM-scoped task. If
you want the agent to run before any user logs in and independent of any user
session, register a second scheduled task manually with
`-User "SYSTEM" -RunLevel Limited -LogonType ServiceAccount` pointed at the
same `olympus-node.cmd` wrapper; this script does not do that for you.

## 4. Verify

```powershell
Get-ScheduledTask -TaskName OlympusNodeAgent | Get-ScheduledTaskInfo
C:\ProgramData\Olympus\node\venv\Scripts\python.exe -m olympus.node_agent status --config C:\ProgramData\Olympus\node\config.json
```

Or run the wrapper directly in the foreground to watch connection logs:

```powershell
C:\ProgramData\Olympus\node\olympus-node.cmd
```

## Uninstall

```powershell
.\Install-OlympusNode.ps1 -InstallRoot "$env:ProgramData\Olympus\node" -Uninstall
```

This stops and unregisters the scheduled task but leaves the install
directory (including `config.json`, which holds the node's private key) in
place. Add `-Force` to also delete `InstallRoot` entirely:

```powershell
.\Install-OlympusNode.ps1 -InstallRoot "$env:ProgramData\Olympus\node" -Uninstall -Force
```

## Security notes

- **No inbound port, ever.** The agent only opens outbound WebSocket
  connections to the control plane; the Scheduled Task runs that outbound
  client. This installer never calls `New-NetFirewallRule` or opens any
  listener.
- **The node key never leaves the machine.** `enroll` generates an Ed25519
  key pair locally inside the agent process and writes the private key only
  to `InstallRoot\config.json`, which this installer locks down with NTFS
  ACLs (`icacls /inheritance:r`) to the owning user and SYSTEM/Administrators
  only. The installer never prints, logs, or transmits the private key.
- **The enrollment token is not persisted and never enters the process
  argument list.** The installer pipes it to the agent on standard input
  (`--enrollment-token-stdin`), so it does not appear in `Get-Process`, in
  `config.json`, in any log file, or in the PowerShell transcript. It is
  single-use and short-lived; if it leaks before redemption, revoke it with
  `DELETE /v1/nodes/enrollments/<token_id>`.
- **Requirements are hash-pinned.** `requirements-node.txt` is installed with
  `--require-hashes`, and the Olympus wheel is installed with `--no-deps`, so
  a compromised index cannot substitute a package.
