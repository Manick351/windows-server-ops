<#
.SYNOPSIS
    Logs an account off every Windows server where it has a session. With -WhatIf only reports where it is logged on.

.DESCRIPTION
    Typical case: an admin or service account password was changed, and stale RDP sessions keep
    locking the account. The script:

      1. builds the server list from -ComputerName or from Active Directory (enabled Windows Server
         computer accounts, domain controllers excluded, optional -SearchBase OUs and -Exclude);
      2. pass 1: connects to all servers in parallel (Invoke-Command fan-out, -ThrottleLimit) and logs
         off every session of the account, disconnected ones included;
      3. pass 2: retries servers that failed, with low parallelism;
      4. stale DNS detection: each server compares the name it was reached by with its real name.
         If they differ (the DNS record points to another host), nothing is done in pass 1; in pass 3
         the action is repeated on those targets only if the host that answered was not processed directly;
      5. unreachable servers are split by the computer account's lastLogonTimestamp into
         "probably alive - check manually" and "stale AD objects".

    Supports -WhatIf (report only) and asks for confirmation once for the whole batch.

.PARAMETER UserName
    sAMAccountName of the account (without domain).

.PARAMETER ComputerName
    Servers to process. If omitted, the list is read from Active Directory.

.PARAMETER SearchBase
    One or more OUs to read servers from. Default: the whole domain.

.PARAMETER Exclude
    Server names to skip.

.PARAMETER ThrottleLimit
    Parallel connections in pass 1. Default: 32.

.PARAMETER StaleDays
    Unreachable servers whose computer account did not log on for this many days are reported as stale. Default: 30.

.PARAMETER Credential
    Optional credential for WinRM.

.EXAMPLE
    .\Invoke-AccountLogoff.ps1 -UserName adm-jdoe -WhatIf

    Shows where the account has sessions, changes nothing.

.EXAMPLE
    .\Invoke-AccountLogoff.ps1 -UserName adm-jdoe -SearchBase 'OU=Servers,DC=contoso,DC=local' -Exclude srv-legacy-01 -Confirm:$false
#>
#Requires -Version 5.1
[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[^\\@]+$')]
    [string]$UserName,

    [string[]]$ComputerName,

    [string[]]$SearchBase,

    [string[]]$Exclude = @(),

    [ValidateRange(1, 256)]
    [int]$ThrottleLimit = 32,

    [ValidateRange(1, 3650)]
    [int]$StaleDays = 30,

    [pscredential]$Credential
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Get-ServerList {
    # Enabled Windows Server computer accounts; SERVER_TRUST_ACCOUNT (8192) = domain controller.
    $filter = '(&(objectCategory=computer)(operatingSystem=*Windows Server*)' +
        '(!(userAccountControl:1.2.840.113556.1.4.803:=2))(!(userAccountControl:1.2.840.113556.1.4.803:=8192)))'
    $roots = if ($SearchBase) { $SearchBase | ForEach-Object { [adsi]"LDAP://$_" } } else { @([adsi]'') }
    foreach ($root in $roots) {
        $searcher = New-Object System.DirectoryServices.DirectorySearcher($root, $filter)
        $searcher.PageSize = 1000
        foreach ($p in 'name', 'dNSHostName', 'lastLogonTimestamp') { [void]$searcher.PropertiesToLoad.Add($p) }
        foreach ($r in $searcher.FindAll()) {
            $name = [string]$r.Properties['name'][0]
            [PSCustomObject]@{
                Name      = $name.ToLower()
                Fqdn      = if ($r.Properties['dnshostname'].Count) { [string]$r.Properties['dnshostname'][0] } else { $name }
                LastLogon = if ($r.Properties['lastlogontimestamp'].Count) { [datetime]::FromFileTime([int64]$r.Properties['lastlogontimestamp'][0]) } else { $null }
            }
        }
    }
}

$remote = {
    param([string]$UserName, [bool]$DoLogoff, [bool]$Force)
    $actual = $env:COMPUTERNAME.ToLower()

    # The name this session was opened with (http://<target>:5985/wsman).
    $target = $null
    if ($PSSenderInfo -and $PSSenderInfo.ConnectionString -match '//([^:/]+)') { $target = ($Matches[1] -split '\.')[0].ToLower() }
    if (-not $Force -and $target -and $target -notmatch '^\d+$' -and $target -ne $actual) {
        return [PSCustomObject]@{ Actual = $actual; Status = 'Mismatch'; Sessions = '' }
    }

    $sessions = foreach ($line in (& query.exe user 2>&1 | ForEach-Object { "$_" })) {
        $t = ($line -replace '^\s*>', '').Trim() -split '\s+'
        if ($t.Count -lt 3) { continue }
        for ($i = 1; $i -lt $t.Count - 1; $i++) {
            if ($t[$i] -match '^\d+$') { [PSCustomObject]@{ User = $t[0]; Id = [int]$t[$i]; State = $t[$i + 1] }; break }
        }
    }
    $mine = @($sessions | Where-Object { $_.User -eq $UserName })
    if (-not $mine) { return [PSCustomObject]@{ Actual = $actual; Status = 'NotFound'; Sessions = '' } }

    if ($DoLogoff) { foreach ($s in $mine) { & logoff.exe $s.Id 2>&1 | Out-Null } }
    [PSCustomObject]@{
        Actual   = $actual
        Status   = if ($DoLogoff) { 'LoggedOff' } else { 'Found' }
        Sessions = ($mine | ForEach-Object { "$($_.Id):$($_.State)" }) -join ', '
    }
}

function Invoke-Pass {
    param([object[]]$Servers, [int]$Throttle, [bool]$DoLogoff, [bool]$Force, [string]$Label)
    if (-not $Servers) { return @() }
    Write-Host "$Label - $($Servers.Count) server(s), throttle $Throttle" -ForegroundColor Cyan
    $byFqdn = @{}
    foreach ($s in $Servers) { $byFqdn[$s.Fqdn.ToLower()] = $s }

    $params = @{
        ComputerName  = @($Servers | ForEach-Object Fqdn)
        ScriptBlock   = $remote
        ArgumentList  = $UserName, $DoLogoff, $Force
        ThrottleLimit = $Throttle
        SessionOption = New-PSSessionOption -OpenTimeout 10000 -OperationTimeout 60000
        ErrorAction   = 'SilentlyContinue'
        ErrorVariable = 'remoteErrors'
    }
    if ($Credential) { $params.Credential = $Credential }
    $replies = @(Invoke-Command @params)

    $rows = foreach ($r in $replies) {
        $server = $byFqdn[$r.PSComputerName.ToLower()]
        if (-not $server) { continue }
        [PSCustomObject]@{ Server = $server.Name; Status = $r.Status; Actual = $r.Actual; Detail = $r.Sessions; LastLogon = $server.LastLogon }
    }
    $rows = @($rows)
    foreach ($e in $remoteErrors) {
        $failed = if ($e.TargetObject) { "$($e.TargetObject)" } elseif ($e.OriginInfo) { $e.OriginInfo.PSComputerName } else { $null }
        if (-not $failed -or -not $byFqdn.ContainsKey($failed.ToLower())) { continue }
        $server = $byFqdn[$failed.ToLower()]
        if ($rows | Where-Object Server -eq $server.Name) { continue }
        $message = ($e.Exception.Message -replace '\s+', ' ')
        if ($message.Length -gt 140) { $message = $message.Substring(0, 140) + '...' }
        $rows += [PSCustomObject]@{ Server = $server.Name; Status = 'Error'; Actual = ''; Detail = $message; LastLogon = $server.LastLogon }
    }
    return $rows
}

# Server list
if ($ComputerName) {
    $servers = @($ComputerName | ForEach-Object { [PSCustomObject]@{ Name = ($_ -split '\.')[0].ToLower(); Fqdn = $_; LastLogon = $null } })
}
else {
    Write-Host 'Reading Windows servers from Active Directory...' -ForegroundColor Cyan
    $servers = @(Get-ServerList)
}
$excludeSet = @($Exclude | ForEach-Object { ($_ -split '\.')[0].ToLower() })
$servers = @($servers | Where-Object { $excludeSet -notcontains $_.Name } | Sort-Object Name -Unique)
if (-not $servers) { throw 'No servers to process.' }

$doLogoff = $PSCmdlet.ShouldProcess("$($servers.Count) server(s)", "Log off all sessions of '$UserName'")
if (-not $doLogoff -and -not $WhatIfPreference) { return }   # answered "No" at the confirmation prompt
$mode = if ($doLogoff) { 'LOG OFF' } else { 'REPORT ONLY (-WhatIf)' }
Write-Host "Account: $UserName   servers: $($servers.Count)   mode: $mode" -ForegroundColor Yellow

$started = Get-Date
$pass1 = Invoke-Pass -Servers $servers -Throttle $ThrottleLimit -DoLogoff $doLogoff -Force $false -Label 'Pass 1'
$failedNames = @($pass1 | Where-Object Status -eq 'Error' | ForEach-Object Server)
$pass2 = Invoke-Pass -Servers @($servers | Where-Object { $failedNames -contains $_.Name }) -Throttle 4 -DoLogoff $doLogoff -Force $false -Label 'Pass 2 (retry failed)'

# Merge: a later pass overrides an earlier error for the same server.
$final = @{}
foreach ($row in @($pass1) + @($pass2)) {
    if (-not $final.ContainsKey($row.Server) -or $final[$row.Server].Status -eq 'Error') { $final[$row.Server] = $row }
}

$reachedHosts = @($final.Values | Where-Object { $_.Status -in 'Found', 'LoggedOff', 'NotFound' } | ForEach-Object Server)
$mismatches = @($final.Values | Where-Object Status -eq 'Mismatch')
$uncovered = @($mismatches | Where-Object { $reachedHosts -notcontains $_.Actual })
foreach ($m in @($mismatches | Where-Object { $reachedHosts -contains $_.Actual })) {
    $m.Detail = "DNS points to $($m.Actual), which was processed directly"
}
$pass3 = Invoke-Pass -Servers @($servers | Where-Object { @($uncovered | ForEach-Object Server) -contains $_.Name }) -Throttle 4 -DoLogoff $doLogoff -Force $true -Label 'Pass 3 (uncovered DNS mismatches)'
foreach ($row in $pass3) {
    $final[$row.Server] = [PSCustomObject]@{ Server = $row.Server; Status = $row.Status; Actual = $row.Actual; Detail = "stale DNS, answered as $($row.Actual); $($row.Detail)"; LastLogon = $row.LastLogon }
}

$results = @($final.Values | Sort-Object Server)
$hit = @($results | Where-Object { $_.Status -in 'Found', 'LoggedOff' })
$errors = @($results | Where-Object Status -eq 'Error')

Write-Host ''
Write-Host ('Done in {0:mm\:ss}. Sessions found on {1} server(s), not found on {2}, DNS mismatches {3}, unreachable {4}, total {5}.' -f
    ((Get-Date) - $started), $hit.Count, @($results | Where-Object Status -eq 'NotFound').Count, $mismatches.Count, $errors.Count, $results.Count) -ForegroundColor Green
foreach ($h in $hit) { Write-Host ('  {0,-22} {1,-10} {2}' -f $h.Server, $h.Status, $h.Detail) -ForegroundColor White }
if ($mismatches) {
    Write-Host 'Stale DNS records (name resolves to a different host):' -ForegroundColor Yellow
    foreach ($m in $mismatches) { Write-Host ('  {0} -> {1}' -f $m.Server, $m.Actual) }
}
if ($errors) {
    $cutoff = (Get-Date).AddDays(-$StaleDays)
    $alive = @($errors | Where-Object { -not $_.LastLogon -or $_.LastLogon -ge $cutoff })
    $stale = @($errors | Where-Object { $_.LastLogon -and $_.LastLogon -lt $cutoff })
    if ($alive) {
        Write-Host "ACTION REQUIRED - unreachable but the computer account is active (a session may remain):" -ForegroundColor Red
        foreach ($a in $alive) { Write-Host ('  {0,-22} {1}' -f $a.Server, $a.Detail) }
    }
    if ($stale) {
        Write-Host "Stale AD objects (no logon for $StaleDays+ days) - candidates for cleanup:" -ForegroundColor DarkYellow
        Write-Host ('  ' + (($stale | ForEach-Object Server) -join ', '))
    }
}

$results
