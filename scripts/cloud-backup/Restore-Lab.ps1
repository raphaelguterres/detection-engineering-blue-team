#requires -Version 5.1
<#
Restore encrypted Restic snapshots into a NEW, EMPTY recovery directory.
Does not overwrite, register, or power on existing VirtualBox VMs.
#>
[CmdletBinding()]
param(
  [ValidateSet('List','Restore','Check')][string]$Action = 'List',
  [string]$SnapshotId = '',
  [string]$Target = ''
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$resticCmd = Get-Command restic.exe -ErrorAction SilentlyContinue
if (-not $resticCmd) { throw 'restic.exe not installed or missing from PATH.' }
if ([string]::IsNullOrWhiteSpace($env:RESTIC_REPOSITORY)) { throw 'RESTIC_REPOSITORY is not set.' }
if ([string]::IsNullOrWhiteSpace($env:RESTIC_PASSWORD_FILE) -or
  -not (Test-Path -LiteralPath $env:RESTIC_PASSWORD_FILE -PathType Leaf)) {
  throw 'RESTIC_PASSWORD_FILE must point to an existing private password file.'
}
if ($Action -eq 'List') {
  & $resticCmd.Source snapshots --tag soc-lab
  if ($LASTEXITCODE -ne 0) { throw 'Snapshot listing failed.' }
  exit 0
}
if ($Action -eq 'Check') {
  & $resticCmd.Source check
  if ($LASTEXITCODE -ne 0) { throw 'Integrity verification failed.' }
  exit 0
}
if ([string]::IsNullOrWhiteSpace($SnapshotId)) { throw 'Supply a specific -SnapshotId from List.' }
if ([string]::IsNullOrWhiteSpace($Target)) { throw 'Supply a dedicated empty -Target directory.' }
$fullTarget = [System.IO.Path]::GetFullPath($Target)
$root = [System.IO.Path]::GetPathRoot($fullTarget)
if ($fullTarget.TrimEnd('\') -eq $root.TrimEnd('\')) { throw 'Refusing to restore into a drive root.' }
if (Test-Path -LiteralPath $fullTarget) {
  if (-not (Test-Path -LiteralPath $fullTarget -PathType Container)) { throw 'Restore target is not a directory.' }
  if (@(Get-ChildItem -LiteralPath $fullTarget -Force -ErrorAction Stop).Count -gt 0) {
    throw 'Refusing restore into a non-empty directory. Pick an empty recovery folder.'
  }
} else {
  New-Item -ItemType Directory -Path $fullTarget -Force | Out-Null
}
Write-Output ("Restoring snapshot " + $SnapshotId + " under " + $fullTarget)
& $resticCmd.Source restore $SnapshotId --target $fullTarget
if ($LASTEXITCODE -ne 0) { throw 'Restore did not complete successfully.' }
Write-Output 'RESTORE_OK: data written to isolated directory. Verify VM files before registering any VM.'
