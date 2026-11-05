#requires -Version 5.1
<#
.SYNOPSIS
  Safe, encrypted, versioned cloud backups for VirtualBox SOC lab folders.
.DESCRIPTION
  Backups are only permitted after every VirtualBox VM has been powered off.
  No VM is stopped, altered, snapshotted, or exported by this script.
  Run locally on the VirtualBox host. No credentials are embedded in this file.
#>
[CmdletBinding()]
param(
  [ValidateSet('Plan','Backup','Snapshots','Check')][string]$Action = 'Plan',
  [string]$ConfigFile = (Join-Path $PSScriptRoot 'lab.local.json')
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if (-not (Test-Path -LiteralPath $ConfigFile -PathType Leaf)) {
  throw "Missing local configuration: $ConfigFile. Copy lab.local.example.json to lab.local.json and adjust the paths."
}
$config = Get-Content -LiteralPath $ConfigFile -Raw -Encoding UTF8 | ConvertFrom-Json
$vmFolders = @($config.vmFolders | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
$extraFolders = @($config.additionalFolders | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
if ($vmFolders.Count -eq 0) { throw 'Configure at least one VM folder.' }
$folders = @($vmFolders + $extraFolders | Select-Object -Unique)

foreach ($folder in $vmFolders) {
  if (-not (Test-Path -LiteralPath $folder -PathType Container)) { throw "VM folder missing: $folder" }
  $vmConfig = @(Get-ChildItem -LiteralPath $folder -File -Filter '*.vbox' -ErrorAction Stop)
  $vmDisk = @(Get-ChildItem -LiteralPath $folder -File -Include '*.vdi','*.vmdk','*.vhd','*.vhdx' -Recurse -ErrorAction Stop)
  if ($vmConfig.Count -eq 0 -or $vmDisk.Count -eq 0) { throw "VM folder lacks a .vbox or disk: $folder" }
}
foreach ($folder in $extraFolders) {
  if (-not (Test-Path -LiteralPath $folder -PathType Container)) { throw "Additional folder missing: $folder" }
}

$vbox = @('C:\Program Files\Oracle\VirtualBox\VBoxManage.exe',
          'C:\Program Files\VirtualBox\VBoxManage.exe') |
  Where-Object { Test-Path -LiteralPath $_ } | Select-Object -First 1
if (-not $vbox) { throw 'VBoxManage.exe not found. Run on the VirtualBox host.' }
$running = @(& $vbox list runningvms 2>&1)
if ($LASTEXITCODE -ne 0) { throw 'Failed to query running VirtualBox machines.' }
$running = @($running | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) })

if ($Action -eq 'Plan') {
  Write-Output ('Folders in backup: ' + $folders.Count)
  $folders | ForEach-Object { Write-Output ("SOURCE: " + $_) }
  Write-Output ('VirtualBox VMs currently running: ' + $running.Count)
  if ($running.Count -gt 0) { Write-Output 'STATUS: NOT READY - gracefully shut down all VirtualBox VMs before backup.' }
  else { Write-Output 'STATUS: VM power-state precheck passed. Configure Restic credentials before backup.' }
  exit 0
}

$resticCmd = Get-Command restic.exe -ErrorAction SilentlyContinue
if (-not $resticCmd) { throw 'restic.exe not found on PATH. Install Restic first.' }
if ([string]::IsNullOrWhiteSpace($env:RESTIC_REPOSITORY)) { throw 'RESTIC_REPOSITORY is not set.' }
if ([string]::IsNullOrWhiteSpace($env:RESTIC_PASSWORD_FILE) -or
    -not (Test-Path -LiteralPath $env:RESTIC_PASSWORD_FILE -PathType Leaf)) {
  throw 'RESTIC_PASSWORD_FILE must point to an existing private password file.'
}
if ($Action -eq 'Snapshots') {
  & $resticCmd.Source snapshots --tag soc-lab
  if ($LASTEXITCODE -ne 0) { throw 'Could not list Restic snapshots.' }
  exit 0
}
if ($Action -eq 'Check') {
  & $resticCmd.Source check
  if ($LASTEXITCODE -ne 0) { throw 'Restic repository integrity check failed.' }
  exit 0
}

if ($running.Count -gt 0) {
  $running | ForEach-Object { Write-Warning ("RUNNING_VM: " + $_) }
  throw 'ABORTED: VirtualBox VMs are running. This backup requires a clean shutdown.'
}
if ([string]::IsNullOrWhiteSpace($env:AWS_ACCESS_KEY_ID) -or
    [string]::IsNullOrWhiteSpace($env:AWS_SECRET_ACCESS_KEY)) {
  throw 'Missing private S3-compatible storage credentials in current process environment.'
}

Write-Output 'STARTING: encrypted offsite Restic snapshot of VM folders and optional evidence folders.'
& $resticCmd.Source backup --tag soc-lab --tag virtualbox -- @folders
if ($LASTEXITCODE -ne 0) { throw 'Cloud backup failed. No successful snapshot claimed.' }
Write-Output 'BACKUP_OK. Listing versioned snapshots:'
& $resticCmd.Source snapshots --tag soc-lab
if ($LASTEXITCODE -ne 0) { throw 'Backup finished but snapshot listing failed; verify repository.' }
