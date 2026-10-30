param([string]$Action, [string]$Scenario, [string]$RunId, [string]$ExpectedHostname)
$ErrorActionPreference = 'Stop'
if ($RunId -notmatch '^DE-[a-f0-9]{16}$') { throw 'INVALID_RUN_ID' }
if (-not $ExpectedHostname -or $env:COMPUTERNAME -ine $ExpectedHostname) { throw 'ENDPOINT_IDENTITY_MISMATCH' }
$channel = 'Microsoft-Windows-Sysmon/Operational'
$name = $RunId
$account = 'DE' + $RunId.Substring(3,12)
$key = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run'

function Get-TestValue {
    if (Test-Path -LiteralPath $key) {
        return (Get-Item -LiteralPath $key).GetValueNames() -contains $name
    }
    return $false
}
function Remove-TestArtifact {
    switch ($Scenario) {
        'schtasks' {
            if (Get-ScheduledTask -TaskName $name -ErrorAction SilentlyContinue) {
                & "$env:SystemRoot\System32\schtasks.exe" /delete /tn $name /f | Out-Null
                if ($LASTEXITCODE -ne 0) { throw 'TASK_CLEANUP_FAILED' }
            }
            if (Get-ScheduledTask -TaskName $name -ErrorAction SilentlyContinue) { throw 'TASK_REMAINS' }
        }
        'runkey' {
            if (Get-TestValue) { Remove-ItemProperty -LiteralPath $key -Name $name }
            if (Get-TestValue) { throw 'RUNKEY_REMAINS' }
        }
        'localaccount' {
            if (Get-LocalUser -Name $account -ErrorAction SilentlyContinue) {
                & "$env:SystemRoot\System32\net.exe" user $account /delete | Out-Null
                if ($LASTEXITCODE -ne 0) { throw 'ACCOUNT_CLEANUP_FAILED' }
            }
            if (Get-LocalUser -Name $account -ErrorAction SilentlyContinue) { throw 'ACCOUNT_REMAINS' }
        }
    }
}
if ($Action -eq 'cleanup') {
    Remove-TestArtifact
    return @{ ok = $true; cleanup = 'verified'; run_id = $RunId }
}
$sysmon = @(Get-Service -Name Sysmon,Sysmon64 -ErrorAction SilentlyContinue | Where-Object Status -eq 'Running')
$agent = Get-Service -Name WazuhSvc -ErrorAction SilentlyContinue
$log = Get-WinEvent -ListLog $channel -ErrorAction SilentlyContinue
$ready = $sysmon.Count -gt 0 -and $agent.Status -eq 'Running' -and $log.IsEnabled
if ($Action -eq 'probe') {
    $recent13 = @(Get-WinEvent -FilterHashtable @{LogName=$channel; Id=13; StartTime=(Get-Date).AddHours(-24)} -MaxEvents 1 -ErrorAction SilentlyContinue)
    return @{ ok = [bool]$ready; identity_verified = $true; sysmon_running = ($sysmon.Count -gt 0); agent_running = ($agent.Status -eq 'Running'); event13_seen_last_24h = ($recent13.Count -gt 0) }
}
if (-not $ready) { throw 'TELEMETRY_SERVICES_NOT_READY' }
$start = Get-Date
$marker = $RunId
$eventId = if ($Scenario -eq 'runkey') { 13 } else { 1 }
$cleanup = 'not_needed'
$errorCode = $null
$ownsArtifact = $false
try {
    switch ($Scenario) {
        'powershell' {
            $marker = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes("Write-Output '$RunId'"))
            & "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -NonInteractive -EncodedCommand $marker | Out-Null
            if ($LASTEXITCODE -ne 0) { throw 'POWERSHELL_FAILED' }
        }
        'rundll32' {
            $dll = "C:\Users\Public\DetectionEngineering\$RunId.dll"
            if (Test-Path -LiteralPath $dll) { throw 'DLL_PATH_ALREADY_EXISTS' }
            $process = Start-Process -FilePath "$env:SystemRoot\System32\rundll32.exe" -ArgumentList "`"$dll,EntryPoint`"" -PassThru -WindowStyle Hidden
            try {
                if (-not $process.WaitForExit(3000)) { $process.Kill(); $process.WaitForExit() }
            } finally { $process.Dispose() }
        }
        'schtasks' {
            if (Get-ScheduledTask -TaskName $name -ErrorAction SilentlyContinue) { throw 'TASK_ALREADY_EXISTS' }
            $ownsArtifact = $true
            # ONSTART avoids locale-sensitive dates; no reboot or task execution occurs.
            & "$env:SystemRoot\System32\schtasks.exe" /create /tn $name /sc ONSTART /tr "cmd.exe /c echo $RunId" | Out-Null
            if ($LASTEXITCODE -ne 0) { throw 'TASK_CREATE_FAILED' }
        }
        'runkey' {
            if (-not (Test-Path -LiteralPath $key)) { throw 'RUN_KEY_NOT_PRESENT' }
            if (Get-TestValue) { throw 'RUN_VALUE_ALREADY_EXISTS' }
            $ownsArtifact = $true
            New-ItemProperty -LiteralPath $key -Name $name -Value "cmd.exe /c echo $RunId" -PropertyType String | Out-Null
        }
        'localaccount' {
            if ((Get-CimInstance Win32_ComputerSystem).DomainRole -ge 4) { throw 'DOMAIN_CONTROLLER_UNSUPPORTED' }
            if (Get-LocalUser -Name $account -ErrorAction SilentlyContinue) { throw 'ACCOUNT_ALREADY_EXISTS' }
            $marker = $account
            # Keep the random password out of process arguments and create a disabled account.
            $password = 'aA1!' + [guid]::NewGuid().ToString('N')
            $securePassword = ConvertTo-SecureString $password -AsPlainText -Force
            $password = $null
            try {
                New-LocalUser -Name $account -Password $securePassword -Disabled -AccountNeverExpires `
                    -PasswordNeverExpires -Description 'Temporary disabled detection engineering test' | Out-Null
            } finally { $securePassword.Dispose() }
            $ownsArtifact = $true
            $created = Get-LocalUser -Name $account
            if ($created.Enabled) { throw 'ACCOUNT_NOT_DISABLED' }

            # The existing disabled account makes this /add a harmless duplicate-create attempt.
            # The command line is the telemetry under test; a nonzero net.exe exit is expected.
            $psi = New-Object Diagnostics.ProcessStartInfo
            $psi.FileName = "$env:SystemRoot\System32\net.exe"
            $psi.Arguments = "user $account * /add /active:no"
            $psi.UseShellExecute = $false
            $psi.CreateNoWindow = $true
            $psi.RedirectStandardInput = $true
            $psi.RedirectStandardOutput = $true
            $psi.RedirectStandardError = $true
            $process = New-Object Diagnostics.Process
            $process.StartInfo = $psi
            try {
                [void]$process.Start()
                $stdout = $process.StandardOutput.ReadToEndAsync()
                $stderr = $process.StandardError.ReadToEndAsync()
                $process.StandardInput.Close()
                if (-not $process.WaitForExit(10000)) { $process.Kill(); $process.WaitForExit(); throw 'ACCOUNT_COMMAND_TIMEOUT' }
            } finally { $process.Dispose() }
        }
        default { throw 'UNKNOWN_SCENARIO' }
    }
} catch {
    $errorCode = if ($_.Exception.Message -match 'ALREADY_EXISTS') { 'ARTIFACT_COLLISION' } else { 'SIMULATION_FAILED' }
}
finally {
    if ($ownsArtifact) {
        try { Remove-TestArtifact; $cleanup = 'verified' }
        catch { $cleanup = 'failed'; $errorCode = 'CLEANUP_FAILED' }
    }
}
$count = 0
for ($attempt=0; $attempt -lt 5; $attempt++) {
    $events = @(Get-WinEvent -FilterHashtable @{LogName=$channel; Id=$eventId; StartTime=$start} -MaxEvents 300 -ErrorAction SilentlyContinue)
    $count = @($events | Where-Object {
        [xml]$xml = $_.ToXml()
        @($xml.Event.EventData.Data | Where-Object {
            $_.Name -in @('CommandLine','TargetObject','Details') -and $_.'#text'.Contains($marker)
        }).Count -gt 0
    }).Count
    if ($count -gt 0) { break }
    Start-Sleep -Seconds 1
}
@{ ok = ($null -eq $errorCode); error = $errorCode; run_id = $RunId; marker = $marker; event_id = $eventId; local_events = $count; cleanup = $cleanup }
