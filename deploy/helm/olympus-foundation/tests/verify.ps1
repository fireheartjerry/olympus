[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$HelmPath,

    [Parameter(Mandatory = $true)]
    [string]$KubeconformPath,

    [Parameter()]
    [string]$KubernetesVersion = "1.36.1",

    [Parameter()]
    [string]$SchemaLocation = "https://raw.githubusercontent.com/yannh/kubernetes-json-schema/05eeed51991935dd1f47cd3b3682de4e8af233f3/{{.NormalizedKubernetesVersion}}-standalone-strict/{{.ResourceKind}}.json"
)

$ErrorActionPreference = "Stop"

$chartPath = Split-Path -Parent $PSScriptRoot
$repositoryRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $chartPath))
$temporaryDirectory = if (-not [string]::IsNullOrWhiteSpace($env:RUNNER_TEMP)) {
    $env:RUNNER_TEMP
} else {
    [IO.Path]::GetTempPath()
}
$renderedPath = Join-Path $temporaryDirectory "olympus-foundation-rendered.yaml"

function Assert-HelmTemplateFails {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Description,

        [Parameter(Mandatory = $true)]
        [string[]]$Arguments
    )

    $output = & $HelmPath @Arguments 2>&1
    if ($LASTEXITCODE -eq 0) {
        throw "Expected Helm template to reject $Description."
    }
    Write-Host "Rejected $Description as expected."
    $output | Write-Host
}

function Assert-HelmTemplateSucceeds {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Description,

        [Parameter(Mandatory = $true)]
        [string[]]$Arguments
    )

    $output = & $HelmPath @Arguments 2>&1
    if ($LASTEXITCODE -ne 0) {
        $output | Write-Host
        throw "Expected Helm template to accept $Description."
    }
    Write-Host "Rendered $Description as expected."
}

& $HelmPath lint --strict $chartPath
if ($LASTEXITCODE -ne 0) {
    throw "Helm lint failed."
}

& $HelmPath template olympus $chartPath --namespace agent-control | Set-Content -Encoding utf8 $renderedPath
if ($LASTEXITCODE -ne 0) {
    throw "Helm template failed."
}

& $KubeconformPath -summary -strict -kubernetes-version $KubernetesVersion -schema-location $SchemaLocation $renderedPath
if ($LASTEXITCODE -ne 0) {
    throw "Kubeconform validation failed."
}

Assert-HelmTemplateSucceeds -Description "all exact guardrail values via --set" -Arguments @(
    "template", "olympus", $chartPath,
    "--set", "namespaces.control=agent-control",
    "--set", "namespaces.data=agent-data",
    "--set", "namespaces.platform=agent-platform",
    "--set", "namespaces.workersLocal=agent-workers-local",
    "--set", "workerQuota.requestsCpuMillicores=3500",
    "--set", "workerQuota.requestsMemoryMib=8704",
    "--set", "workerQuota.limitsMemoryMib=10752",
    "--set", "workerQuota.pods=8"
)

Assert-HelmTemplateFails -Description "a changed CPU quota" -Arguments @(
    "template", "olympus", $chartPath, "--set", "workerQuota.requestsCpuMillicores=3501"
)
Assert-HelmTemplateFails -Description "a changed worker namespace" -Arguments @(
    "template", "olympus", $chartPath, "--set", "namespaces.workersLocal=other-workers"
)
Assert-HelmTemplateFails -Description "a bogus top-level value" -Arguments @(
    "template", "olympus", $chartPath, "--set", "bogusOverride=enabled"
)
Assert-HelmTemplateFails -Description "a string quota value" -Arguments @(
    "template", "olympus", $chartPath, "--set-string", "workerQuota.requestsCpuMillicores=3500"
)
Assert-HelmTemplateFails -Description "a fractional quota value" -Arguments @(
    "template", "olympus", $chartPath, "--set", "workerQuota.requestsCpuMillicores=3500.5"
)
Assert-HelmTemplateFails -Description "a changed quota with schema validation skipped" -Arguments @(
    "template", "olympus", $chartPath, "--skip-schema-validation", "--set", "workerQuota.requestsCpuMillicores=3501"
)
Assert-HelmTemplateFails -Description "a changed worker namespace with schema validation skipped" -Arguments @(
    "template", "olympus", $chartPath, "--skip-schema-validation", "--set", "namespaces.workersLocal=other-workers"
)
Assert-HelmTemplateFails -Description "a bogus top-level value with schema validation skipped" -Arguments @(
    "template", "olympus", $chartPath, "--skip-schema-validation", "--set", "bogusOverride=enabled"
)
Assert-HelmTemplateFails -Description "a string quota value with schema validation skipped" -Arguments @(
    "template", "olympus", $chartPath, "--skip-schema-validation", "--set-string", "workerQuota.requestsCpuMillicores=3500"
)
Assert-HelmTemplateFails -Description "a fractional quota value with schema validation skipped" -Arguments @(
    "template", "olympus", $chartPath, "--skip-schema-validation", "--set", "workerQuota.requestsCpuMillicores=3500.5"
)

${env:OLYMPUS_RENDERED_PATH} = $renderedPath
${env:OLYMPUS_CAPACITY_PATH} = Join-Path $repositoryRoot "config/capacity/vps4.yaml"

@'
import os
from pathlib import Path

import yaml

capacity = yaml.safe_load(Path(os.environ["OLYMPUS_CAPACITY_PATH"]).read_text(encoding="utf-8"))
rendered_path = Path(os.environ["OLYMPUS_RENDERED_PATH"])
rendered = [item for item in yaml.safe_load_all(rendered_path.read_text(encoding="utf-8-sig")) if item]

assert len(rendered) == 8
assert [item["kind"] for item in rendered] == [
    "PriorityClass", "PriorityClass", "PriorityClass",
    "Namespace", "Namespace", "Namespace", "Namespace", "ResourceQuota",
]
assert [(item["metadata"]["name"], item["value"], item.get("preemptionPolicy")) for item in rendered[:3]] == [
    ("olympus-control", 100000, None),
    ("olympus-platform", 50000, None),
    ("olympus-worker", -10000, "Never"),
]
for namespace in rendered[3:7]:
    annotations = namespace["metadata"]["annotations"]
    assert annotations["helm.sh/resource-policy"] == "keep"
    assert annotations["olympus.dev/network-policy-status"] == "not-installed"
    assert annotations["olympus.dev/workload-admission"] == "blocked-until-network-policy-security-slice"
for priority in rendered[:3]:
    assert priority["metadata"]["annotations"]["helm.sh/resource-policy"] == "keep"
quota = rendered[-1]
assert quota["metadata"]["namespace"] == "agent-workers-local"
assert quota["metadata"]["annotations"]["helm.sh/resource-policy"] == "keep"
assert quota["spec"]["hard"] == {
    "requests.cpu": f"{capacity['worker_quota']['cpu_request_millicores']}m",
    "requests.memory": f"{capacity['worker_quota']['memory_request_mib']}Mi",
    "limits.memory": f"{capacity['worker_quota']['memory_limit_mib']}Mi",
    "pods": "8",
}
print("Rendered guardrails exactly match the VPS-4 CapacityPlan.")
'@ | & uv run --project $repositoryRoot python -
if ($LASTEXITCODE -ne 0) {
    throw "Rendered CapacityPlan comparison failed."
}
