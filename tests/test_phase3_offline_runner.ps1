# Synthetic CI smoke test. Never connects to Wazuh or real hosts.
Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
$repository = Split-Path -Parent $PSScriptRoot
$lab = Join-Path $repository ".lab"
if (Test-Path -LiteralPath $lab) {
    throw "Expected fresh isolated CI workspace."
}
New-Item -ItemType Directory -Path $lab | Out-Null

$record = @{
    id = "synthetic-ci-event-001"
    timestamp = "2026-10-30T20:00:00Z"
    rule = @{ id = "110130" }
    agent = @{ id = "004" }
}
$json = $record | ConvertTo-Json -Depth 5 -Compress
$json | Set-Content -LiteralPath (Join-Path $lab "phase3-manager.jsonl") -Encoding UTF8
$json | Set-Content -LiteralPath (Join-Path $lab "phase3-indexer.jsonl") -Encoding UTF8

$runner = Join-Path $repository "scripts/phase3-run-offline.ps1"
for ($attempt = 1; $attempt -le 2; $attempt++) {
    $result = @(& $runner -StartUtc "2026-10-30T00:00:00Z" -EndUtc "2026-10-31T00:00:00Z")
    $display = [string]::Join([Environment]::NewLine, [string[]]$result)
    if (-not $display.Contains("PHASE3_OFFLINE_HANDOFF_COMPLETED")) {
        throw "Offline handoff did not complete."
    }
    if (-not $display.Contains("Dashboard validation: NOT PERFORMED")) {
        throw "Offline run must not claim Dashboard evidence."
    }
    $files = @(Get-ChildItem -LiteralPath $lab -Filter "phase3-observations-*.json")
    if ($files.Count -ne $attempt) {
        throw "A new observation file was not generated for this run."
    }
}
foreach ($file in @(Get-ChildItem -LiteralPath $lab -Filter "phase3-observations-*.json")) {
    $record = Get-Content -LiteralPath $file.FullName -Raw | ConvertFrom-Json
    if ($record.'110130'.manager -ne "found") { throw "Manager evidence absent." }
    if ($record.'110130'.indexer -ne "found") { throw "Indexer evidence absent." }
    if ($record.'110130'.dashboard -ne "unknown") { throw "Dashboard must remain unknown." }
    if ($record.'110130'.same_event_verified -ne $false) {
        throw "Offline matching must never mark end-to-end verified."
    }
}
Write-Output "PHASE3_OFFLINE_SMOKE_PASS"
