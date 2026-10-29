param(
    [Parameter(Mandatory)][string]$ConfigPath,
    [ValidateSet('probe','run','cleanup')][string]$Action = 'probe',
    [ValidateSet('powershell','rundll32','schtasks','runkey','localaccount')][string]$Scenario = 'powershell',
    [ValidatePattern('^DE-[a-f0-9]{16}$')][string]$RunId = 'DE-0000000000000000'
)
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
try {
    $config = Get-Content -LiteralPath $ConfigPath -Raw | ConvertFrom-Json
    if ($config.isolated_lab -ne $true) { throw 'ISOLATED_LAB_REQUIRED' }
    $w = $config.windows
    if ($w.authentication -notin @('Negotiate','Kerberos')) { throw 'UNSUPPORTED_AUTHENTICATION' }
    $parameters = @{
        ComputerName = $w.computer_name
        Authentication = $w.authentication
        UseSSL = [bool]$w.use_ssl
        SessionOption = New-PSSessionOption -OpenTimeout 10000 -OperationTimeout 90000
        ScriptBlock = [scriptblock]::Create((Get-Content -LiteralPath (Join-Path $PSScriptRoot 'windows-worker.ps1') -Raw))
        ArgumentList = @($Action, $Scenario, $RunId, $w.expected_hostname)
    }
    if ($w.credential_path) {
        $credential = Import-Clixml -LiteralPath $w.credential_path
        if ($credential -isnot [pscredential]) { throw 'INVALID_CREDENTIAL_FILE' }
        $parameters.Credential = $credential
    }
    $result = Invoke-Command @parameters
    $result | Select-Object * -ExcludeProperty PSComputerName,RunspaceId,PSShowComputerName | ConvertTo-Json -Depth 8 -Compress
} catch {
    # Error text can contain hostnames, usernames or command lines; keep it local in memory.
    @{ ok = $false; error = 'WINDOWS_REMOTE_FAILED'; category = [string]$_.CategoryInfo.Category } | ConvertTo-Json -Compress
    exit 1
}
