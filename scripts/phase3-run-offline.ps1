# Offline-only Phase 3 Manager/Indexer evidence handoff.
# No VM contact, authentication, simulation, or service changes.
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$StartUtc,
    [Parameter(Mandatory = $true)]
    [string]$EndUtc,
    [string]$Manager = ".lab/phase3-manager.jsonl",
    [string]$Indexer = ".lab/phase3-indexer.jsonl"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$repository = Split-Path -Parent $PSScriptRoot
Push-Location -LiteralPath $repository
try {
    $privateRoot = Join-Path $repository ".lab"
    if (-not (Test-Path -LiteralPath $privateRoot -PathType Container)) {
        throw "Private .lab/ directory is missing; no evidence processed."
    }
    $privateItem = Get-Item -LiteralPath $privateRoot -Force
    if (($privateItem.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "Private .lab/ directory must not be a link."
    }

    $runId = [guid]::NewGuid().ToString("N")
    $comparison = Join-Path $privateRoot "phase3-comparison-$runId.json"
    $observations = Join-Path $privateRoot "phase3-observations-$runId.json"

    # Read existing private exports only. Python validates their paths and timestamps.
    $lines = @(& python scripts/phase3_compare_alert_exports.py --manager $Manager --indexer $Indexer --start-utc $StartUtc --end-utc $EndUtc)
    if ($LASTEXITCODE -ne 0 -or $lines.Count -eq 0) {
        throw "Historical comparison failed; no observation draft created."
    }
    $summary = [string]::Join([Environment]::NewLine, [string[]]$lines)
    $null = $summary | ConvertFrom-Json -ErrorAction Stop

    # A unique file name plus NoClobber protects against stale results.
    $summary | Out-File -LiteralPath $comparison -Encoding UTF8 -NoClobber -ErrorAction Stop

    & python scripts/phase3_prepare_observations.py --comparison $comparison --output $observations
    if ($LASTEXITCODE -ne 0) {
        throw "Offline observation draft failed."
    }

    $decision = @(& python scripts/phase3_evidence_gate.py $observations)
    if ($LASTEXITCODE -ne 0 -or $decision.Count -eq 0) {
        throw "Offline evidence classification failed."
    }
    $null = ([string]::Join([Environment]::NewLine, [string[]]$decision) | ConvertFrom-Json -ErrorAction Stop)

    Write-Output "PHASE3_OFFLINE_HANDOFF_COMPLETED"
    Write-Output ("Comparison and observations saved under ignored .lab/ with run ID " + $runId)
    Write-Output ([string]::Join([Environment]::NewLine, [string[]]$decision))
    Write-Output "Dashboard validation: NOT PERFORMED"
}
finally {
    Pop-Location
}
