#Requires -Version 5.1
<#
.SYNOPSIS
    Installs, updates, or uninstalls the Olympus execution-node agent on Windows.

.DESCRIPTION
    This installer never opens an inbound firewall port and never creates a
    listening socket. The agent's `run` subcommand dials OUT to the control
    plane over an outbound-only WebSocket; the Scheduled Task it registers
    runs that outbound client. Nothing listens on this machine.

    The agent's Ed25519 node key pair is generated ON THIS MACHINE, inside the
    agent process, during `enroll`. This script never generates, embeds,
    prints, or logs that key. The enrollment token supplied to -EnrollmentToken
    is passed to the agent process as a parameter at run time; it is never
    written to a log file, transcript, or the config file.

.PARAMETER ControlPlaneUrl
    Base URL of the Olympus control plane, e.g. https://vps-41e741fc.tail70f263.ts.net

.PARAMETER EnrollmentToken
    Single-use enrollment token issued by the control plane. Accepts a
    SecureString or a plain string. Required unless -SkipEnrollment is set.

.PARAMETER NodeName
    Name to register this node under. Defaults to $env:COMPUTERNAME.

.PARAMETER InstallRoot
    Directory the agent is installed into. Defaults to
    "$env:ProgramData\Olympus\node". If InstallRoot is under ProgramData,
    this script must be run elevated (Administrator).

.PARAMETER PackagePath
    Path to the locally built olympus .whl file.

.PARAMETER PythonExe
    Explicit path to a Python 3.13 interpreter, used only if py -3.13 and
    python3.13 cannot be located on PATH.

.PARAMETER SkipEnrollment
    Install/update the venv and scheduled task, but do not run `enroll`.
    Requires that a valid config already exists.

.PARAMETER Force
    Re-enroll even if a config already exists. Combined with -Uninstall,
    also removes InstallRoot entirely (including the config/key material).

.PARAMETER Uninstall
    Stop and unregister the scheduled task. Leaves InstallRoot (and the
    config/key material inside it) in place unless -Force is also passed.

.EXAMPLE
    .\Install-OlympusNode.ps1 -ControlPlaneUrl "https://vps-41e741fc.tail70f263.ts.net" `
        -EnrollmentToken $token -NodeName "jerry-windows" -PackagePath "C:\temp\olympus-0.1.0-py3-none-any.whl"
#>
[CmdletBinding(DefaultParameterSetName = 'Install')]
param(
    [Parameter(ParameterSetName = 'Install', Mandatory = $true)]
    [string]$ControlPlaneUrl,

    [Parameter(ParameterSetName = 'Install')]
    [object]$EnrollmentToken,

    [Parameter(ParameterSetName = 'Install')]
    [string]$NodeName = $env:COMPUTERNAME,

    [Parameter(ParameterSetName = 'Install')]
    [Parameter(ParameterSetName = 'Uninstall')]
    [string]$InstallRoot = (Join-Path $env:ProgramData 'Olympus\node'),

    [Parameter(ParameterSetName = 'Install', Mandatory = $true)]
    [string]$PackagePath,

    [Parameter(ParameterSetName = 'Install')]
    [string]$PythonExe,

    [Parameter(ParameterSetName = 'Install')]
    [switch]$SkipEnrollment,

    [Parameter(ParameterSetName = 'Install')]
    [Parameter(ParameterSetName = 'Uninstall')]
    [switch]$Force,

    [Parameter(ParameterSetName = 'Uninstall', Mandatory = $true)]
    [switch]$Uninstall
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$TaskName = 'OlympusNodeAgent'

function Write-Status {
    param(
        [Parameter(Mandatory = $true)][ValidateSet('ok', 'skip', 'change')]$Kind,
        [Parameter(Mandatory = $true)][string]$Message
    )
    Write-Host "[$Kind] $Message"
}

function ConvertTo-PlainText {
    param([object]$Value)
    if ($null -eq $Value) {
        return $null
    }
    if ($Value -is [System.Security.SecureString]) {
        $bstr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($Value)
        try {
            return [System.Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)
        } finally {
            [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
        }
    }
    return [string]$Value
}

function Assert-Prerequisites {
    if ($PSVersionTable.PSVersion -lt [version]'5.1') {
        throw "PowerShell 5.1 or later is required (found $($PSVersionTable.PSVersion))."
    }
    if (-not $IsWindowsOverride) {
        throw "This installer only runs on Windows."
    }
    Write-Status ok "PowerShell $($PSVersionTable.PSVersion) on Windows."
}

function Test-IsAdministrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Assert-ElevationIfNeeded {
    param([string]$Root)
    $programData = [Environment]::GetFolderPath('CommonApplicationData')
    $needsAdmin = $Root.TrimEnd('\').StartsWith($programData.TrimEnd('\'), [StringComparison]::OrdinalIgnoreCase)
    if ($needsAdmin -and -not (Test-IsAdministrator)) {
        throw "InstallRoot '$Root' is under ProgramData; this script must be run as Administrator."
    }
    if ($needsAdmin) {
        Write-Status ok "Running elevated, required because InstallRoot is under ProgramData."
    } else {
        Write-Status ok "InstallRoot is outside ProgramData; running as the current user (no elevation required)."
    }
}

function Find-Python313 {
    param([string]$ExplicitPath)

    $candidate = $null
    try {
        $pyLauncherOutput = & py -3.13 -c "import sys; print(sys.executable)" 2>$null
        if ($LASTEXITCODE -eq 0 -and $pyLauncherOutput) {
            $candidate = $pyLauncherOutput.Trim()
        }
    } catch {
        # py launcher not present; fall through
    }

    if (-not $candidate) {
        $found = Get-Command python3.13 -ErrorAction SilentlyContinue
        if ($found) {
            $candidate = $found.Source
        }
    }

    if (-not $candidate -and $ExplicitPath) {
        if (Test-Path -LiteralPath $ExplicitPath) {
            $candidate = $ExplicitPath
        }
    }

    if (-not $candidate) {
        throw "Could not locate Python 3.13. Install it from https://www.python.org/downloads/ (or via 'winget install Python.Python.3.13'), then re-run with -PythonExe pointing at python.exe if it is not on PATH. This script will not install Python for you."
    }

    $versionOutput = & $candidate -c "import sys; print('%d.%d' % sys.version_info[:2])"
    if ($versionOutput.Trim() -ne '3.13') {
        throw "Python at '$candidate' reports version $($versionOutput.Trim()), expected 3.13."
    }

    Write-Status ok "Using Python 3.13 at $candidate"
    return $candidate
}

function New-InstallDirectories {
    param([string]$Root)

    $created = $false
    if (-not (Test-Path -LiteralPath $Root)) {
        New-Item -ItemType Directory -Path $Root -Force | Out-Null
        $created = $true
    }
    $statePath = Join-Path $Root 'state'
    if (-not (Test-Path -LiteralPath $statePath)) {
        New-Item -ItemType Directory -Path $statePath -Force | Out-Null
        $created = $true
    }

    if ($created) {
        Write-Status change "Created install directories under $Root."
    } else {
        Write-Status skip "Install directories already exist under $Root."
    }

    # Lock down NTFS ACLs: only the owning user and SYSTEM/Administrators can
    # read this tree, since the config file holds the node's private key.
    $currentUser = "$([Security.Principal.WindowsIdentity]::GetCurrent().Name)"
    & icacls $Root /inheritance:r | Out-Null
    & icacls $Root /grant:r "${currentUser}:(OI)(CI)F" | Out-Null
    & icacls $Root /grant:r "SYSTEM:(OI)(CI)F" | Out-Null
    & icacls $Root /grant:r "Administrators:(OI)(CI)F" | Out-Null
    Write-Status ok "NTFS ACLs restricted to $currentUser, SYSTEM, and Administrators on $Root."

    return $statePath
}

function Initialize-Venv {
    param([string]$PythonPath, [string]$Root)

    $venvPath = Join-Path $Root 'venv'
    $venvPython = Join-Path $venvPath 'Scripts\python.exe'

    if (Test-Path -LiteralPath $venvPython) {
        Write-Status skip "Virtual environment already exists at $venvPath."
    } else {
        & $PythonPath -m venv $venvPath
        if ($LASTEXITCODE -ne 0) {
            throw "Failed to create virtual environment at $venvPath."
        }
        Write-Status change "Created virtual environment at $venvPath."
    }

    return $venvPython
}

function Install-Dependencies {
    param([string]$VenvPython, [string]$WheelPath)

    $requirementsPath = Join-Path $PSScriptRoot 'requirements-node.txt'
    if (-not (Test-Path -LiteralPath $requirementsPath)) {
        throw "requirements-node.txt not found next to this script at $requirementsPath."
    }
    if (-not (Test-Path -LiteralPath $WheelPath)) {
        throw "PackagePath '$WheelPath' does not exist."
    }

    & $VenvPython -m pip install --upgrade "pip==25.2"
    if ($LASTEXITCODE -ne 0) {
        throw "Failed to upgrade pip."
    }
    Write-Status ok "pip upgraded to a pinned version."

    & $VenvPython -m pip install --require-hashes -r $requirementsPath
    if ($LASTEXITCODE -ne 0) {
        throw "Failed to install hash-pinned dependencies from $requirementsPath."
    }
    Write-Status ok "Runtime dependencies installed from requirements-node.txt (hash-verified)."

    & $VenvPython -m pip install --no-deps --force-reinstall $WheelPath
    if ($LASTEXITCODE -ne 0) {
        throw "Failed to install the olympus wheel from $WheelPath."
    }
    Write-Status ok "olympus wheel installed from $WheelPath (--no-deps)."
}

function Invoke-Enrollment {
    param(
        [string]$VenvPython,
        [string]$ConfigPath,
        [string]$Url,
        [object]$Token,
        [string]$Name,
        [bool]$ForceEnroll
    )

    if (-not $Token) {
        throw "EnrollmentToken is required unless -SkipEnrollment is set."
    }

    if ((Test-Path -LiteralPath $ConfigPath) -and -not $ForceEnroll) {
        Write-Status skip "Config already exists at $ConfigPath; not re-enrolling (pass -Force to re-enroll)."
        return
    }

    $plainToken = ConvertTo-PlainText -Value $Token

    $arguments = @(
        '-m', 'olympus.node_agent', 'enroll',
        '--control-plane-url', $Url,
        '--enrollment-token-stdin',
        '--node-name', $Name,
        '--kind', 'workstation',
        '--config', $ConfigPath
    )
    if ($ForceEnroll) {
        $arguments += '--force'
    }

    # The token is piped on stdin so it never appears in the process argument
    # list, in a transcript, or in any log. It is cleared immediately after.
    $plainToken | & $VenvPython @arguments
    $exitCode = $LASTEXITCODE
    $plainToken = $null
    [System.GC]::Collect()

    if ($exitCode -eq 2) {
        Write-Status skip "Agent reported config already present; not re-enrolling."
        return
    }
    if ($exitCode -ne 0) {
        throw "Enrollment failed (exit code $exitCode). See agent output above for details."
    }
    Write-Status change "Enrolled node '$Name' with the control plane."
}

function New-Wrapper {
    param([string]$Root, [string]$VenvPython, [string]$ConfigPath)

    $wrapperPath = Join-Path $Root 'olympus-node.cmd'
    $content = @"
@echo off
REM Runs the Olympus node agent's outbound-only session client.
REM No inbound port is opened and no listening socket is created by this process.
"$VenvPython" -m olympus.node_agent run --config "$ConfigPath" --state-directory "$Root\state"
"@
    $existing = $null
    if (Test-Path -LiteralPath $wrapperPath) {
        $existing = Get-Content -LiteralPath $wrapperPath -Raw
    }
    if ($existing -eq $content) {
        Write-Status skip "Wrapper script already up to date at $wrapperPath."
    } else {
        Set-Content -LiteralPath $wrapperPath -Value $content -Encoding ASCII
        Write-Status change "Wrote wrapper script at $wrapperPath."
    }
    return $wrapperPath
}

function Register-AgentTask {
    param([string]$WrapperPath, [string]$Root)

    $action = New-ScheduledTaskAction -Execute $WrapperPath -WorkingDirectory $Root
    $triggers = @(
        (New-ScheduledTaskTrigger -AtStartup),
        (New-ScheduledTaskTrigger -AtLogOn)
    )
    $settings = New-ScheduledTaskSettingsSet `
        -RestartCount 999 `
        -RestartInterval (New-TimeSpan -Minutes 1) `
        -ExecutionTimeLimit ([TimeSpan]::Zero) `
        -StartWhenAvailable `
        -AllowStartIfOnBatteries `
        -DontStopIfGoingOnBatteries

    # RunLevel Limited (not Highest): the agent does not need admin rights to
    # dial out over an outbound WebSocket. Runs only while a session exists
    # (RunOnlyIfLoggedOn-style user task) unless InstallRoot is ProgramData,
    # in which case a SYSTEM-scoped task is documented in README.md as an
    # alternative that this script does not select automatically.
    $principal = New-ScheduledTaskPrincipal -UserId $env:USERNAME -LogonType Interactive -RunLevel Limited

    $task = New-ScheduledTask -Action $action -Trigger $triggers -Settings $settings -Principal $principal
    Register-ScheduledTask -TaskName $TaskName -InputObject $task -Force | Out-Null
    Write-Status change "Registered/updated scheduled task '$TaskName' (AtStartup + AtLogon, RunLevel Limited)."
}

function Start-AgentTask {
    Start-ScheduledTask -TaskName $TaskName
    Start-Sleep -Seconds 2
    $info = Get-ScheduledTask -TaskName $TaskName | Get-ScheduledTaskInfo
    $task = Get-ScheduledTask -TaskName $TaskName
    if ($task.State -eq 'Running') {
        Write-Status ok "Scheduled task '$TaskName' is running."
    } else {
        Write-Status change "Scheduled task '$TaskName' state is '$($task.State)' (LastTaskResult: $($info.LastTaskResult))."
    }
}

function Invoke-UninstallFlow {
    param([string]$Root, [bool]$ForceRemove)

    $existingTask = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
    if ($existingTask) {
        Stop-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
        Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
        Write-Status change "Stopped and unregistered scheduled task '$TaskName'."
    } else {
        Write-Status skip "Scheduled task '$TaskName' was not registered."
    }

    if ($ForceRemove) {
        if (Test-Path -LiteralPath $Root) {
            Remove-Item -LiteralPath $Root -Recurse -Force
            Write-Status change "Removed InstallRoot entirely: $Root (including config and key material)."
        } else {
            Write-Status skip "InstallRoot $Root did not exist."
        }
    } else {
        Write-Status ok "Left InstallRoot in place (config/key material preserved): $Root. Pass -Force to remove it."
    }
}

$IsWindowsOverride = ($env:OS -eq 'Windows_NT') -or ($PSVersionTable.PSEdition -eq 'Desktop')

try {
    Assert-Prerequisites

    if ($Uninstall) {
        Assert-ElevationIfNeeded -Root $InstallRoot
        Invoke-UninstallFlow -Root $InstallRoot -ForceRemove:$Force.IsPresent
        exit 0
    }

    Assert-ElevationIfNeeded -Root $InstallRoot

    $pythonPath = Find-Python313 -ExplicitPath $PythonExe
    New-InstallDirectories -Root $InstallRoot | Out-Null
    $venvPython = Initialize-Venv -PythonPath $pythonPath -Root $InstallRoot
    Install-Dependencies -VenvPython $venvPython -WheelPath $PackagePath

    $configPath = Join-Path $InstallRoot 'config.json'
    if (-not $SkipEnrollment) {
        Invoke-Enrollment -VenvPython $venvPython -ConfigPath $configPath -Url $ControlPlaneUrl `
            -Token $EnrollmentToken -Name $NodeName -ForceEnroll:$Force.IsPresent
    } elseif (-not (Test-Path -LiteralPath $configPath)) {
        throw "SkipEnrollment was set but no config exists at $configPath."
    } else {
        Write-Status skip "SkipEnrollment set; using existing config at $configPath."
    }

    $wrapperPath = New-Wrapper -Root $InstallRoot -VenvPython $venvPython -ConfigPath $configPath
    Register-AgentTask -WrapperPath $wrapperPath -Root $InstallRoot
    Start-AgentTask

    Write-Host ""
    Write-Status ok "Olympus node agent install complete."
} catch {
    Write-Host "[fail] $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}
