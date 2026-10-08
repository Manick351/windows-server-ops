<#
.SYNOPSIS
    Compares LAPS configuration of a working computer with a broken one and shows what differs.

.DESCRIPTION
    When LAPS writes a password for one server but not for another, the cause is usually one of:
    the GPO does not apply (OU link or security filtering), the managed local account does not exist,
    the client is missing, or the client logs an error. This script collects the same facts from both
    computers over WinRM and prints them side by side, highlighting the differences:

      - Windows LAPS client present (laps.dll) and legacy AdmPwd CSE;
      - policy registry values (GPO, local/CSP and legacy branches): backup directory, account name,
        password age, legacy enable flag;
      - applied computer GPOs (from gpresult) and those with "LAPS" in the name;
      - managed account: exists, enabled; built-in Administrator (RID 500) name and state;
      - last error from the Microsoft-Windows-LAPS/Operational log.

    No passwords are read.

.PARAMETER Reference
    Computer where LAPS works.

.PARAMETER Difference
    Computer where LAPS does not work.

.PARAMETER Credential
    Optional credential for WinRM.

.EXAMPLE
    .\Compare-LapsConfiguration.ps1 -Reference srv-app-01 -Difference srv-app-07
#>
#Requires -Version 5.1
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$Reference,
    [Parameter(Mandatory = $true)][string]$Difference,
    [pscredential]$Credential
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$probe = {
    $o = [ordered]@{}
    $o.WindowsLapsClient = Test-Path "$env:SystemRoot\System32\laps.dll"
    $o.LegacyLapsCse = Test-Path "$env:ProgramFiles\LAPS\CSE\AdmPwd.dll"

    $branches = [ordered]@{
        Gpo    = 'HKLM:\Software\Microsoft\Policies\LAPS'
        Local  = 'HKLM:\Software\Microsoft\Windows\LAPS\Config'
        Legacy = 'HKLM:\Software\Policies\Microsoft Services\AdmPwd'
    }
    foreach ($b in $branches.Keys) {
        $exists = Test-Path $branches[$b]
        $o["$b.Exists"] = $exists
        $p = if ($exists) { Get-ItemProperty $branches[$b] } else { $null }
        foreach ($v in 'BackupDirectory', 'AdministratorAccountName', 'PasswordAgeDays', 'AdmPwdEnabled') {
            $o["$b.$v"] = if ($p -and $p.PSObject.Properties[$v]) { $p.$v } else { '' }
        }
    }

    $applied = @()
    $capture = $false
    foreach ($line in (& gpresult.exe /r /scope:computer 2>$null)) {
        if ($line -match 'Applied Group Policy Objects') { $capture = $true; continue }
        if (-not $capture) { continue }
        if ($line -match '^\s*-{3,}') { continue }
        if (-not $line.Trim()) { break }
        $applied += $line.Trim()
    }
    $o.AppliedGpos = $applied -join ' | '
    $o.LapsGpos = ($applied | Where-Object { $_ -match 'LAPS' }) -join ' | '

    $account = $null
    foreach ($b in 'Gpo', 'Local') { if ($o["$b.AdministratorAccountName"]) { $account = $o["$b.AdministratorAccountName"] } }
    $o.ManagedAccount = if ($account) { $account } else { '(built-in Administrator)' }
    if ($account) {
        $user = Get-LocalUser -Name $account -ErrorAction SilentlyContinue
        $o.ManagedAccountExists = [bool]$user
        $o.ManagedAccountEnabled = if ($user) { $user.Enabled } else { '' }
    }
    $builtin = Get-LocalUser | Where-Object { $_.SID.Value -like '*-500' }
    $o.BuiltinAdminName = $builtin.Name
    $o.BuiltinAdminEnabled = $builtin.Enabled

    try {
        $err = Get-WinEvent -LogName 'Microsoft-Windows-LAPS/Operational' -MaxEvents 50 -ErrorAction Stop |
            Where-Object Level -eq 2 | Select-Object -First 1
        $o.LastLapsError = if ($err) { 'Id {0} at {1:yyyy-MM-dd HH:mm}: {2}' -f $err.Id, $err.TimeCreated, ("$($err.Message)" -split "`n")[0].Trim() } else { '(none)' }
    }
    catch { $o.LastLapsError = '(log not available)' }

    [PSCustomObject]$o
}

$data = @{}
foreach ($pair in @(@{ Name = $Reference; Role = 'Reference' }, @{ Name = $Difference; Role = 'Difference' })) {
    Write-Host "Collecting from $($pair.Name) ($($pair.Role))..." -ForegroundColor Yellow
    $params = @{ ComputerName = $pair.Name; ScriptBlock = $probe; ErrorAction = 'Stop' }
    if ($Credential) { $params.Credential = $Credential }
    try { $data[$pair.Role] = Invoke-Command @params }
    catch { throw "Cannot collect data from $($pair.Name): $($_.Exception.Message)" }
}

$keys = @($data.Reference.PSObject.Properties.Name | Where-Object { $_ -notin 'PSComputerName', 'RunspaceId', 'PSShowComputerName' })
$rows = foreach ($k in $keys) {
    $r = "$($data.Reference.$k)"
    $d = "$($data.Difference.$k)"
    [PSCustomObject]@{ Field = $k; $Reference = $r; $Difference = $d; Same = ($r -eq $d) }
}

$fmt = '{0,-34} | {1,-36} | {2,-36}'
Write-Host ($fmt -f 'FIELD', "$Reference (reference)", "$Difference (difference)") -ForegroundColor White
foreach ($row in $rows) {
    Write-Host ($fmt -f $row.Field, $row.$Reference, $row.$Difference) -ForegroundColor $(if ($row.Same) { 'DarkGray' } else { 'Yellow' })
}

Write-Host ''
Write-Host 'How to read the differences:' -ForegroundColor Cyan
Write-Host '  Gpo.Exists True vs False           -> the LAPS GPO does not reach the second computer (OU link, filtering, WMI filter).'
Write-Host '  Same policy, ManagedAccountExists False -> policy is fine, but the managed local account was never created.'
Write-Host '  LapsGpos differ                    -> the name of the GPO that is missing on the second computer.'
Write-Host '  No differences                     -> check SELF write permission on the OU (Set-LapsADComputerSelfPermission) and encryption settings.'

$rows | Where-Object { -not $_.Same }
