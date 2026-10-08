<#
.SYNOPSIS
    Watches an account on every domain controller and reports each failed password attempt and lockout as it happens.

.DESCRIPTION
    badPwdCount, badPasswordTime and lockoutTime are not replicated between domain controllers, so the
    DC that a client talks to is the only one that sees its bad password. The script polls all DCs over
    LDAP (no ActiveDirectory module needed), remembers the previous state and logs:

      - every increase of badPwdCount on a DC, with the time of the attempt;
      - lockout and unlock moments.

    Knowing which DC registered the failures narrows the source down to the clients in that site.
    With -QueryPdcEvents the script also reads event 4740 from the PDC emulator, which contains the
    Caller Computer Name (requires rights to read the Security log on the PDC).

.PARAMETER UserName
    sAMAccountName to watch.

.PARAMETER IntervalSeconds
    Polling interval. Default: 60.

.PARAMETER DurationHours
    How long to watch. Default: 24.

.PARAMETER Once
    Print the current state on all DCs and exit.

.PARAMETER QueryPdcEvents
    On lockout, read event 4740 for this account from the PDC emulator.

.PARAMETER LogPath
    Folder for the daily log file. Default: %USERPROFILE%\LockoutWatch.

.EXAMPLE
    .\Watch-AccountLockout.ps1 -UserName svc-backup -Once

.EXAMPLE
    .\Watch-AccountLockout.ps1 -UserName jdoe -IntervalSeconds 30 -QueryPdcEvents
#>
#Requires -Version 5.1
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$UserName,
    [ValidateRange(5, 3600)][int]$IntervalSeconds = 60,
    [ValidateRange(1, 168)][int]$DurationHours = 24,
    [switch]$Once,
    [switch]$QueryPdcEvents,
    [string]$LogPath = (Join-Path $env:USERPROFILE 'LockoutWatch')
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if (-not (Test-Path -LiteralPath $LogPath)) { New-Item -ItemType Directory -Path $LogPath -Force | Out-Null }
$logFile = Join-Path $LogPath ('lockout_{0}_{1:yyyy-MM-dd}.log' -f $UserName, (Get-Date))

function Write-Log {
    param([string]$Text, [ConsoleColor]$Color = 'Gray')
    $line = '[{0:yyyy-MM-dd HH:mm:ss}] {1}' -f (Get-Date), $Text
    Write-Host $line -ForegroundColor $Color
    [IO.File]::AppendAllText($logFile, $line + "`r`n", [Text.Encoding]::UTF8)
}

function ConvertTo-Int64 {
    # LDAP large integers come back as COM objects (IADsLargeInteger) or Int64 depending on the provider.
    param($Raw)
    if ($null -eq $Raw) { return [int64]0 }
    if ($Raw -is [int64] -or $Raw -is [int]) { return [int64]$Raw }
    if ($Raw -is [System.__ComObject]) {
        $hi = $Raw.GetType().InvokeMember('HighPart', 'GetProperty', $null, $Raw, $null)
        $lo = $Raw.GetType().InvokeMember('LowPart', 'GetProperty', $null, $Raw, $null)
        return ([int64]$hi -shl 32) -bor [uint32]$lo
    }
    return [int64]0
}

function Format-FileTime {
    param([int64]$Value)
    if ($Value -le 0) { return '-' }
    try { return [datetime]::FromFileTime($Value).ToString('yyyy-MM-dd HH:mm:ss') } catch { return '-' }
}

$domain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
$dcs = @($domain.DomainControllers | ForEach-Object { $_.Name })
$pdc = $null
try { $pdc = $domain.PdcRoleOwner.Name } catch { }
$domainDn = ([adsi]'LDAP://RootDSE').defaultNamingContext.Value

Write-Log "Domain $($domain.Name): $($dcs.Count) domain controller(s), PDC emulator: $pdc" Green
Write-Log "Watching: $UserName   log: $logFile" Green

function Get-AccountState {
    param([string]$Dc)
    $searcher = New-Object System.DirectoryServices.DirectorySearcher([adsi]"LDAP://$Dc/$domainDn")
    $searcher.Filter = "(&(objectCategory=person)(objectClass=user)(sAMAccountName=$UserName))"
    foreach ($p in 'badPwdCount', 'badPasswordTime', 'lockoutTime') { [void]$searcher.PropertiesToLoad.Add($p) }
    $r = $searcher.FindOne()
    if (-not $r) { return $null }
    $get = { param($n) if ($r.Properties[$n].Count) { $r.Properties[$n][0] } else { $null } }
    [PSCustomObject]@{
        BadPwdCount = [int](& $get 'badpwdcount')
        BadPwdTime  = ConvertTo-Int64 (& $get 'badpasswordtime')
        LockoutTime = ConvertTo-Int64 (& $get 'lockouttime')
    }
}

function Show-PdcLockoutEvents {
    if (-not $pdc) { return }
    try {
        $filter = "*[System[EventID=4740]] and *[EventData[Data[@Name='TargetUserName']='$UserName']]"
        Get-WinEvent -ComputerName $pdc -LogName Security -FilterXPath $filter -MaxEvents 5 -ErrorAction Stop | ForEach-Object {
            $xml = [xml]$_.ToXml()
            $caller = ($xml.Event.EventData.Data | Where-Object Name -eq 'TargetDomainName').'#text'
            Write-Log ("    4740 on {0} at {1:yyyy-MM-dd HH:mm:ss}: Caller Computer Name = {2}" -f $pdc, $_.TimeCreated, $caller) Yellow
        }
    }
    catch { Write-Log "    Cannot read 4740 from $pdc : $($_.Exception.Message)" DarkYellow }
}

$previous = @{}
$deadline = (Get-Date).AddHours($DurationHours)
$first = $true
while ($true) {
    foreach ($dc in $dcs) {
        try { $state = Get-AccountState $dc }
        catch { if ($first) { Write-Log "  $dc unreachable: $($_.Exception.Message)" DarkYellow }; continue }
        if (-not $state) { if ($first) { Write-Log "  $dc : account not found" Red }; continue }

        $prev = $previous[$dc]
        if ($first) {
            Write-Log ('  {0}: badPwdCount={1}  lastBadPassword={2}  lockout={3}' -f $dc, $state.BadPwdCount, (Format-FileTime $state.BadPwdTime), (Format-FileTime $state.LockoutTime))
        }
        elseif ($prev) {
            if ($state.BadPwdCount -gt $prev.BadPwdCount) {
                Write-Log ('!!! FAILED ATTEMPT on {0}: badPwdCount {1} -> {2} at {3}' -f $dc, $prev.BadPwdCount, $state.BadPwdCount, (Format-FileTime $state.BadPwdTime)) Red
            }
            if ($state.LockoutTime -gt 0 -and $prev.LockoutTime -eq 0) {
                Write-Log ('!!! LOCKED OUT (registered on {0}) at {1}' -f $dc, (Format-FileTime $state.LockoutTime)) Red
                if ($QueryPdcEvents) { Show-PdcLockoutEvents }
                else { Write-Log '    Check event 4740 on the PDC emulator (Caller Computer Name) and 4771/4776 on the DCs above.' Yellow }
            }
            if ($state.LockoutTime -eq 0 -and $prev.LockoutTime -gt 0) { Write-Log "    unlocked on $dc" Green }
        }
        $previous[$dc] = $state
    }
    if ($first) {
        $first = $false
        if ($Once) { break }
        Write-Log "Watching every $IntervalSeconds s until $($deadline.ToString('yyyy-MM-dd HH:mm')). Stop with Ctrl+C." Cyan
    }
    if ((Get-Date) -ge $deadline) { Write-Log 'Watch period ended.' Cyan; break }
    Start-Sleep -Seconds $IntervalSeconds
}
