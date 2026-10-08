<#
.SYNOPSIS
    Creates a Zabbix maintenance window for a list of hosts (for example before patching), via the JSON-RPC API.

.DESCRIPTION
    Looks the hosts up by their technical name, creates a one-time maintenance period starting now and
    returns the maintenance ID. Hosts not found in Zabbix are reported.

    Authentication:
      - API token (Zabbix 6.4+): sent as "Authorization: Bearer <token>" - recommended;
      - user name and password: user.login is called and the session is logged out at the end
        (use -LegacyAuth for Zabbix older than 6.4, where the session id goes into the request body).

.PARAMETER Url
    Zabbix frontend URL, for example https://zabbix.contoso.local/zabbix.

.PARAMETER HostName
    Host names as configured in Zabbix ("host" field).

.PARAMETER Hours
    Length of the maintenance window. Default: 8.

.PARAMETER Name
    Maintenance name. Default: "Windows patching <timestamp>".

.PARAMETER ApiToken
    Zabbix API token as a SecureString.

.PARAMETER Credential
    Zabbix user name and password.

.PARAMETER LegacyAuth
    Put the session id into the request body (Zabbix before 6.4).

.PARAMETER NoData
    Maintenance without data collection (default: with data collection).

.EXAMPLE
    $token = Get-Secret -Name ZabbixApiToken
    .\New-ZabbixMaintenance.ps1 -Url https://zabbix.contoso.local/zabbix -ApiToken $token -HostName srv-app-01, srv-app-02 -Hours 4
#>
#Requires -Version 5.1
[CmdletBinding(SupportsShouldProcess = $true, DefaultParameterSetName = 'Token')]
param(
    [Parameter(Mandatory = $true)][string]$Url,
    [Parameter(Mandatory = $true)][string[]]$HostName,
    [ValidateRange(1, 168)][int]$Hours = 8,
    [string]$Name = ('Windows patching {0:yyyy-MM-dd HH:mm}' -f (Get-Date)),

    [Parameter(Mandatory = $true, ParameterSetName = 'Token')][securestring]$ApiToken,
    [Parameter(Mandatory = $true, ParameterSetName = 'Login')][pscredential]$Credential,
    [Parameter(ParameterSetName = 'Login')][switch]$LegacyAuth,

    [switch]$NoData
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$api = $Url.TrimEnd('/') + '/api_jsonrpc.php'
$script:RequestId = 0
$script:Session = $null

function Invoke-ZabbixApi {
    param([string]$Method, $Params, [switch]$Anonymous)
    $script:RequestId++
    $body = [ordered]@{ jsonrpc = '2.0'; method = $Method; params = $Params; id = $script:RequestId }
    $headers = @{ 'Content-Type' = 'application/json-rpc' }
    if (-not $Anonymous) {
        if ($PSCmdlet.ParameterSetName -eq 'Token') { $headers.Authorization = 'Bearer ' + (New-Object System.Net.NetworkCredential('', $ApiToken)).Password }
        elseif ($LegacyAuth) { $body.auth = $script:Session }
        else { $headers.Authorization = "Bearer $script:Session" }
    }
    $response = Invoke-RestMethod -Uri $api -Method Post -Headers $headers -Body ($body | ConvertTo-Json -Depth 10) -UseBasicParsing
    if ($response.PSObject.Properties['error'] -and $response.error) { throw "Zabbix API $Method failed: $($response.error.message) $($response.error.data)" }
    return $response.result
}

try {
    if ($PSCmdlet.ParameterSetName -eq 'Login') {
        $script:Session = Invoke-ZabbixApi 'user.login' @{ username = $Credential.UserName; password = $Credential.GetNetworkCredential().Password } -Anonymous
    }

    $hosts = @(Invoke-ZabbixApi 'host.get' @{ output = @('hostid', 'host'); filter = @{ host = @($HostName) } })
    $found = @($hosts | ForEach-Object host)
    $missing = @($HostName | Where-Object { $found -notcontains $_ })
    if ($missing) { Write-Warning "Not found in Zabbix: $($missing -join ', ')" }
    if (-not $hosts) { throw 'None of the hosts exist in Zabbix.' }

    $now = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
    $params = @{
        name             = $Name
        active_since     = $now
        active_till      = $now + $Hours * 3600
        description      = "Created by $env:USERDOMAIN\$env:USERNAME on $env:COMPUTERNAME"
        maintenance_type = if ($NoData) { 1 } else { 0 }
        hosts            = @($hosts | ForEach-Object { @{ hostid = $_.hostid } })
        timeperiods      = @(@{ timeperiod_type = 0; start_date = $now; period = $Hours * 3600 })
    }
    if (-not $PSCmdlet.ShouldProcess("$($hosts.Count) host(s)", "Create Zabbix maintenance '$Name' for $Hours h")) { return }
    $result = Invoke-ZabbixApi 'maintenance.create' $params
    Write-Host "Maintenance '$Name' created for $($hosts.Count) host(s), id $($result.maintenanceids -join ',')" -ForegroundColor Green
    [PSCustomObject]@{ MaintenanceId = ($result.maintenanceids -join ','); Hosts = $found; Missing = $missing; Until = (Get-Date).AddHours($Hours) }
}
finally {
    if ($script:Session) { try { [void](Invoke-ZabbixApi 'user.logout' @()) } catch { } }
}
