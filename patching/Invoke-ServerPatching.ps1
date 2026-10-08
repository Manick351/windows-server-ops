<#
.SYNOPSIS
    Patches many Windows servers in parallel: installs updates, reboots with a concurrency limit, verifies services.
    Dry run by default.

.DESCRIPTION
    Orchestrator for monthly patching from a jump host. Every server is processed by its own worker in a
    runspace pool (-ThrottleLimit servers at a time). A worker:

      1. connects over WinRM, trying the credentials from -Credential in order (for example a domain
         account first, then a local administrator for workgroup servers);
      2. takes a snapshot: OS, domain role, last boot, free space on C:, pending reboot, running automatic services;
         domain controllers are skipped unless -IncludeDomainControllers;
      3. in dry run: lists available updates (PSWindowsUpdate) and stops;
      4. optionally stops services matching -HoldServicePattern (application services that must be
         stopped in a controlled way) and remembers their start type;
      5. if a reboot is already pending, reboots first (Auto), waits for approval (Manual) or continues (Never);
      6. installs updates through a one-time scheduled task running as SYSTEM (the Windows Update API refuses
         to download and install from a remote session), polling its progress log;
      7. reboots when required, taking a slot from a shared semaphore so no more than -MaxParallelReboots
         servers are down at the same time, and waits until LastBootUpTime changes (timeout -RebootTimeoutMinutes);
      8. repeats install + reboot up to -MaxInstallRounds times (some updates appear only after a reboot);
      9. restores held services, then compares automatic services with the snapshot taken before the first
         reboot and tries to start the ones that are not running.

    Progress of every server is written to <WorkFolder>\status\<server>.json (read it with Get-PatchingStatus.ps1)
    and an event log to <WorkFolder>\logs\<server>.tsv. The operator can steer single servers with
    Set-PatchingControl.ps1: Stop (abort after the current step) or Reboot (approve a reboot in Manual mode).

    Optionally a Zabbix maintenance window is created for all servers before the run (New-ZabbixMaintenance.ps1).

.PARAMETER ComputerName
    Servers to patch.

.PARAMETER ScheduleCsv
    CSV with columns Name, Window (for example 09:00-12:00) and optional Description. Use with -Window.

.PARAMETER Window
    Process only CSV rows whose window lies inside this one, for example 18:00-23:59.

.PARAMETER Credential
    One or more credentials tried in order. If omitted, the current user is used.

.PARAMETER Execute
    Install updates and reboot. Without it the run only reports pending reboots and available updates.

.PARAMETER RebootMode
    Auto (default), Manual (wait for Set-PatchingControl -Action Reboot) or Never.

.PARAMETER ThrottleLimit
    Servers processed in parallel. Default: 20.

.PARAMETER MaxParallelReboots
    Servers allowed to be rebooting at the same time. Default: 10.

.PARAMETER RebootTimeoutMinutes
    How long to wait for a server to come back. Default: 60.

.PARAMETER InstallTimeoutMinutes
    Maximum time for one install round. Default: 240.

.PARAMETER MaxInstallRounds
    Install + reboot rounds per server. Default: 2.

.PARAMETER HoldServicePattern
    Regex of service display names to stop before installing and start again at the end.

.PARAMETER IncludeDomainControllers
    Patch domain controllers too (skipped by default: patch them separately, one at a time).

.PARAMETER PSWindowsUpdateSource
    Folder with the PSWindowsUpdate module copied to servers that do not have it.

.PARAMETER WorkFolder
    Folder for status, logs and control files. Default: .\PatchRun_<timestamp>.

.PARAMETER ZabbixUrl
    Create a Zabbix maintenance window for the servers (with -ZabbixApiToken).

.PARAMETER ZabbixApiToken
    Zabbix API token (SecureString).

.PARAMETER TimeoutHours
    Stop waiting for workers after this time. Default: 12.

.EXAMPLE
    .\Invoke-ServerPatching.ps1 -ComputerName (Get-Content .\servers.txt)

    Dry run: pending reboots and available updates per server.

.EXAMPLE
    $creds = (Get-Credential CONTOSO\adm-patch), (Import-Clixml C:\Secure\local-admin.xml)
    .\Invoke-ServerPatching.ps1 -ScheduleCsv .\schedule.csv -Window 18:00-23:59 -Credential $creds -Execute `
        -MaxParallelReboots 5 -HoldServicePattern '^Contoso\.(Print|Link)' -ZabbixUrl https://zabbix.contoso.local/zabbix -ZabbixApiToken (Get-Secret ZabbixApiToken)

.NOTES
    Requires the PSWindowsUpdate module on target servers (or -PSWindowsUpdateSource) and WinRM.
#>
#Requires -Version 5.1
[CmdletBinding(DefaultParameterSetName = 'ByName')]
param(
    [Parameter(Mandatory = $true, ParameterSetName = 'ByName')]
    [string[]]$ComputerName,

    [Parameter(Mandatory = $true, ParameterSetName = 'BySchedule')]
    [string]$ScheduleCsv,

    [Parameter(ParameterSetName = 'BySchedule')]
    [ValidatePattern('^\d{1,2}:\d{2}-\d{1,2}:\d{2}$')]
    [string]$Window,

    [pscredential[]]$Credential,

    [switch]$Execute,

    [ValidateSet('Auto', 'Manual', 'Never')]
    [string]$RebootMode = 'Auto',

    [ValidateRange(1, 200)][int]$ThrottleLimit = 20,
    [ValidateRange(1, 200)][int]$MaxParallelReboots = 10,
    [ValidateRange(5, 600)][int]$RebootTimeoutMinutes = 60,
    [ValidateRange(10, 1440)][int]$InstallTimeoutMinutes = 240,
    [ValidateRange(1, 5)][int]$MaxInstallRounds = 2,

    [string]$HoldServicePattern,
    [switch]$IncludeDomainControllers,
    [string]$PSWindowsUpdateSource,
    [string]$WorkFolder = (Join-Path (Get-Location).Path ('PatchRun_{0:yyyyMMdd_HHmm}' -f (Get-Date))),

    [string]$ZabbixUrl,
    [securestring]$ZabbixApiToken,

    [ValidateRange(1, 48)][int]$TimeoutHours = 12
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

#region Server list

function Test-TimeInWindow {
    # True if window A (row) lies inside window B (filter). "00:00" as an end means midnight.
    param([string]$Row, [string]$Filter)
    $parse = {
        param($w)
        $a, $b = $w -split '-'
        $start = [timespan]::Parse($a.Trim())
        $end = if ($b.Trim() -in '0:00', '00:00', '23:59', '24:00') { [timespan]::FromHours(24) } else { [timespan]::Parse($b.Trim()) }
        , @($start, $end)
    }
    $r = & $parse $Row
    $f = & $parse $Filter
    return ($r[0] -ge $f[0] -and $r[1] -le $f[1])
}

if ($PSCmdlet.ParameterSetName -eq 'BySchedule') {
    $rows = @(Import-Csv -LiteralPath $ScheduleCsv)
    if ($Window) { $rows = @($rows | Where-Object { $_.Window -and (Test-TimeInWindow $_.Window $Window) }) }
    $servers = @($rows | ForEach-Object { $_.Name.Trim().ToLower() } | Where-Object { $_ } | Sort-Object -Unique)
}
else {
    $servers = @($ComputerName | ForEach-Object { $_.Trim().ToLower() } | Where-Object { $_ } | Sort-Object -Unique)
}
$servers = @($servers | Where-Object { ($_ -split '\.')[0] -ne [Environment]::MachineName.ToLower() })   # never patch the jump host itself
if (-not $servers) { throw 'No servers to process.' }

#endregion

foreach ($sub in 'status', 'logs', 'control', 'results') { New-Item -ItemType Directory -Path (Join-Path $WorkFolder $sub) -Force | Out-Null }
$mode = if ($Execute) { 'EXECUTE' } else { 'DRY RUN' }
Write-Host ("Patching {0} server(s) | mode {1} | reboot {2} | parallel {3} | reboots {4} | work folder {5}" -f
    $servers.Count, $mode, $RebootMode, $ThrottleLimit, $MaxParallelReboots, $WorkFolder) -ForegroundColor $(if ($Execute) { 'Yellow' } else { 'Green' })

if ($Execute -and $ZabbixUrl) {
    if (-not $ZabbixApiToken) { throw 'Use -ZabbixApiToken with -ZabbixUrl.' }
    try {
        & (Join-Path $PSScriptRoot 'New-ZabbixMaintenance.ps1') -Url $ZabbixUrl -ApiToken $ZabbixApiToken `
            -HostName @($servers | ForEach-Object { ($_ -split '\.')[0] }) -Hours ([Math]::Min($TimeoutHours, 12)) -Confirm:$false | Out-Null
    }
    catch { Write-Warning "Zabbix maintenance not created: $($_.Exception.Message)" }
}

#region Worker

$worker = {
    param([string]$Server, [hashtable]$Options, [object[]]$Credentials, [System.Threading.SemaphoreSlim]$RebootSlots)
    $ErrorActionPreference = 'Stop'
    $statusFile = Join-Path $Options.WorkFolder "status\$Server.json"
    $logFile = Join-Path $Options.WorkFolder "logs\$Server.tsv"
    $controlFile = Join-Path $Options.WorkFolder "control\$Server.txt"
    $state = [ordered]@{
        Server = $Server; Stage = 'Starting'; Result = ''; Connection = ''; AuthUsed = ''; OS = ''; FreeGB = $null
        RebootPending = $null; Reboots = 0; Available = $null; Installed = 0; Failed = 0; ServicesNotStarted = ''
        Started = (Get-Date).ToString('s'); Finished = ''; LastUpdate = ''; Message = ''
    }

    function Write-Event {
        param([string]$Event, [string]$Detail = '')
        $line = "{0}`t{1}`t{2}" -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Event, ($Detail -replace '[\t\r\n]+', ' ')
        for ($i = 0; $i -lt 3; $i++) { try { [IO.File]::AppendAllText($logFile, $line + "`r`n", [Text.Encoding]::UTF8); break } catch { Start-Sleep -Milliseconds 100 } }
    }
    function Set-Status {
        param([string]$Stage, [hashtable]$Fields = @{}, [switch]$NoEvent)
        $state.Stage = $Stage
        foreach ($k in $Fields.Keys) { $state[$k] = $Fields[$k] }
        $state.LastUpdate = (Get-Date).ToString('s')
        $tmp = "$statusFile.tmp"
        [IO.File]::WriteAllText($tmp, ([PSCustomObject]$state | ConvertTo-Json), [Text.Encoding]::UTF8)
        Move-Item -LiteralPath $tmp -Destination $statusFile -Force
        if (-not $NoEvent) { Write-Event 'Stage' $Stage }
    }
    function Get-Control {
        if (Test-Path -LiteralPath $controlFile) { return (Get-Content -LiteralPath $controlFile -Raw).Trim() }
        return ''
    }
    function Clear-Control { Remove-Item -LiteralPath $controlFile -Force -ErrorAction SilentlyContinue }
    function Assert-NotStopped {
        if ((Get-Control) -eq 'Stop') { Clear-Control; throw [System.OperationCanceledException]::new('Stopped by operator') }
    }

    function New-ServerSession {
        param([switch]$Quiet)
        $option = New-PSSessionOption -OpenTimeout 15000 -OperationTimeout 120000
        $list = if ($Credentials) { $Credentials } else { @($null) }
        foreach ($c in $list) {
            try {
                $p = @{ ComputerName = $Server; SessionOption = $option; ErrorAction = 'Stop' }
                if ($c) { $p.Credential = $c }
                $s = New-PSSession @p
                $state.AuthUsed = if ($c) { $c.UserName } else { 'current user' }
                return $s
            }
            catch { if (-not $Quiet) { Write-Event 'ConnectFailed' "$($state.AuthUsed): $($_.Exception.Message)" } }
        }
        return $null
    }

    $snapshotScript = {
        $os = Get-CimInstance Win32_OperatingSystem
        $cbs = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing'
        $pending = (Test-Path "$cbs\RebootPending") -or (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired')
        try {
            $ccm = Invoke-CimMethod -Namespace root\ccm\ClientSDK -ClassName CCM_ClientUtilities -MethodName DetermineIfRebootPending -ErrorAction Stop
            if ($ccm.RebootPending) { $pending = $true }
        }
        catch { }
        [PSCustomObject]@{
            OS         = $os.Caption -replace '^Microsoft ', ''
            LastBoot   = $os.LastBootUpTime
            DomainRole = (Get-CimInstance Win32_ComputerSystem).DomainRole
            FreeGB     = [Math]::Round((Get-PSDrive -Name ($env:SystemDrive.TrimEnd(':'))).Free / 1GB, 1)
            Pending    = [bool]$pending
            AutoRunning = @(Get-Service | Where-Object { $_.StartType -eq 'Automatic' -and $_.Status -eq 'Running' } | ForEach-Object Name)
            HasModule  = [bool](Get-Module -ListAvailable -Name PSWindowsUpdate)
        }
    }

    function Restart-AndWait {
        param($Session)
        if ($Options.RebootMode -eq 'Never') { Write-Event 'RebootSkipped' 'RebootMode=Never'; return $Session }
        if ($Options.RebootMode -eq 'Manual') {
            Set-Status 'Waiting for reboot approval'
            while ((Get-Control) -notin 'Reboot', 'Stop') { Start-Sleep -Seconds 15 }
            Assert-NotStopped
            Clear-Control
        }
        Set-Status 'Waiting for a reboot slot'
        while (-not $RebootSlots.Wait(15000)) { Assert-NotStopped }
        # The slot is held from here on and released in finally, also when the reboot fails.
        try {
            $before = Invoke-Command -Session $Session -ScriptBlock { (Get-CimInstance Win32_OperatingSystem).LastBootUpTime }
            Set-Status 'Rebooting' @{ Connection = 'Rebooting' }
            Invoke-Command -Session $Session -ScriptBlock { Restart-Computer -Force } -ErrorAction SilentlyContinue
            Remove-PSSession -Session $Session -ErrorAction SilentlyContinue
            $state['Reboots'] = $state['Reboots'] + 1
            $deadline = (Get-Date).AddMinutes($Options.RebootTimeoutMinutes)
            Start-Sleep -Seconds 60
            while ((Get-Date) -lt $deadline) {
                $s = New-ServerSession -Quiet
                if ($s) {
                    $boot = Invoke-Command -Session $s -ScriptBlock { (Get-CimInstance Win32_OperatingSystem).LastBootUpTime } -ErrorAction SilentlyContinue
                    if ($boot -and $boot -gt $before) {
                        Write-Event 'RebootDone' "LastBoot=$boot"
                        Set-Status 'Back online' @{ Connection = 'Online' }
                        return $s
                    }
                    Remove-PSSession -Session $s -ErrorAction SilentlyContinue
                }
                Start-Sleep -Seconds 30
            }
            throw "Server did not come back within $($Options.RebootTimeoutMinutes) minutes"
        }
        finally { [void]$RebootSlots.Release() }
    }

    function Install-Updates {
        param($Session)
        if (-not (Invoke-Command -Session $Session -ScriptBlock { [bool](Get-Module -ListAvailable -Name PSWindowsUpdate) })) {
            if (-not $Options.ModuleSource) { throw 'PSWindowsUpdate is not installed on the server and -PSWindowsUpdateSource is not set' }
            Set-Status 'Copying PSWindowsUpdate'
            Copy-Item -ToSession $Session -Path $Options.ModuleSource -Destination 'C:\Program Files\WindowsPowerShell\Modules\PSWindowsUpdate' -Recurse -Force
        }
        Set-Status 'Installing updates'
        $taskScript = @'
$ErrorActionPreference = 'Continue'
$dir = Join-Path $env:SystemRoot 'Temp\PatchRun'
$log = Join-Path $dir 'progress.log'
function Write-Progress2([string]$t) { Add-Content -LiteralPath $log -Value ("{0:HH:mm:ss} {1}" -f (Get-Date), $t) -Encoding UTF8 }
Import-Module PSWindowsUpdate
if ((Get-Service wuauserv).StartType -eq 'Disabled') { Set-Service wuauserv -StartupType Manual; Write-Progress2 'wuauserv was disabled, set to Manual' }
$updates = @(Get-WindowsUpdate)
$results = @()
if (-not $updates) { Write-Progress2 'NO_UPDATES' }
foreach ($u in $updates) {
    Write-Progress2 ("Installing {0} {1}" -f $u.KB, $u.Title)
    $out = Install-WindowsUpdate -UpdateID $u.Identity.UpdateID -AcceptAll -IgnoreReboot -Confirm:$false
    $final = $out | Where-Object { $_.Result -notin 'Accepted', 'Downloaded' } | Select-Object -First 1
    $results += [PSCustomObject]@{ KB = $u.KB; Title = $u.Title; Result = if ($final) { "$($final.Result)" } else { 'Unknown' } }
}
$results | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $dir 'results.json') -Encoding UTF8
Write-Progress2 'DONE'
'@
        Invoke-Command -Session $Session -ArgumentList $taskScript -ScriptBlock {
            param($Script)
            $dir = Join-Path $env:SystemRoot 'Temp\PatchRun'
            New-Item -ItemType Directory -Path $dir -Force | Out-Null
            Remove-Item -Path "$dir\*" -Force -ErrorAction SilentlyContinue
            Set-Content -LiteralPath "$dir\install.ps1" -Value $Script -Encoding UTF8
            $action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$dir\install.ps1`""
            $principal = New-ScheduledTaskPrincipal -UserId 'NT AUTHORITY\SYSTEM' -LogonType ServiceAccount -RunLevel Highest
            $settings = New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Hours 6) -AllowStartIfOnBatteries
            Register-ScheduledTask -TaskName 'PatchRun-Install' -Action $action -Principal $principal -Settings $settings -Force | Out-Null
            Start-ScheduledTask -TaskName 'PatchRun-Install'
        }
        $deadline = (Get-Date).AddMinutes($Options.InstallTimeoutMinutes)
        $last = ''
        do {
            Start-Sleep -Seconds 60
            $progress = Invoke-Command -Session $Session -ErrorAction SilentlyContinue -ScriptBlock {
                $log = Join-Path $env:SystemRoot 'Temp\PatchRun\progress.log'
                [PSCustomObject]@{
                    Last   = if (Test-Path $log) { (Get-Content -LiteralPath $log -Tail 1) } else { '' }
                    State  = "$((Get-ScheduledTask -TaskName 'PatchRun-Install' -ErrorAction SilentlyContinue).State)"
                    FreeGB = [Math]::Round((Get-PSDrive -Name ($env:SystemDrive.TrimEnd(':'))).Free / 1GB, 1)
                }
            }
            if ($progress -and $progress.Last -ne $last) {
                $last = $progress.Last
                Set-Status ('Installing: ' + ($last -replace '^\S+\s', '')) @{ FreeGB = $progress.FreeGB }
            }
            if ((Get-Control) -eq 'Stop') { Write-Event 'StopRequested' 'installation continues on the server, no further steps will run' }
        } while ((Get-Date) -lt $deadline -and (-not $progress -or ($progress.Last -notmatch 'DONE$' -and $progress.State -eq 'Running')))

        $results = @(Invoke-Command -Session $Session -ScriptBlock {
                $dir = Join-Path $env:SystemRoot 'Temp\PatchRun'
                $file = Join-Path $dir 'results.json'
                if (Test-Path $file) { Get-Content -LiteralPath $file -Raw | ConvertFrom-Json }
                Unregister-ScheduledTask -TaskName 'PatchRun-Install' -Confirm:$false -ErrorAction SilentlyContinue
            })
        foreach ($r in $results) { Write-Event 'Update' "$($r.KB) $($r.Result) $($r.Title)" }
        $state.Installed += @($results | Where-Object { $_.Result -match 'Installed|Succeeded' }).Count
        $state.Failed += @($results | Where-Object { $_.Result -match 'Failed|Aborted' }).Count
        if ((Get-Date) -ge $deadline) { throw "Installation did not finish within $($Options.InstallTimeoutMinutes) minutes" }
        return $results.Count
    }

    $session = $null
    $held = @()
    $servicesBefore = @()
    try {
        Set-Status 'Connecting'
        $session = New-ServerSession
        if (-not $session) { throw [System.Management.Automation.RemoteException]::new('Cannot connect with any of the credentials') }
        $snap = Invoke-Command -Session $session -ScriptBlock $snapshotScript
        $servicesBefore = @($snap.AutoRunning)
        Set-Status 'Connected' @{ Connection = 'Online'; OS = $snap.OS; FreeGB = $snap.FreeGB; RebootPending = $snap.Pending }
        if ($snap.FreeGB -lt 5) { Write-Event 'LowDisk' "$($snap.FreeGB) GB free on the system drive" }

        if ($snap.DomainRole -ge 4 -and -not $Options.IncludeDCs) { Set-Status 'Skipped' @{ Result = 'Skipped'; Message = 'domain controller' }; return }

        if (-not $Options.Execute) {
            $available = if ($snap.HasModule) {
                @(Invoke-Command -Session $session -ScriptBlock { Import-Module PSWindowsUpdate; Get-WindowsUpdate | ForEach-Object { "$($_.KB) $($_.Title)" } } -ErrorAction SilentlyContinue)
            }
            else { @() }
            foreach ($a in $available) { Write-Event 'Available' $a }
            $note = if (-not $snap.HasModule) { 'PSWindowsUpdate not installed: cannot list updates' } else { '' }
            Set-Status 'Dry run complete' @{ Result = 'DryRun'; Available = $available.Count; Message = $note }
            return
        }

        if ($Options.HoldPattern) {
            Set-Status 'Stopping held services'
            $held = @(Invoke-Command -Session $session -ArgumentList $Options.HoldPattern -ScriptBlock {
                    param($Pattern)
                    foreach ($s in (Get-Service | Where-Object { $_.DisplayName -match $Pattern -and $_.Status -eq 'Running' })) {
                        $startType = "$($s.StartType)"
                        Stop-Service -Name $s.Name -Force
                        Set-Service -Name $s.Name -StartupType Disabled
                        [PSCustomObject]@{ Name = $s.Name; DisplayName = $s.DisplayName; StartType = $startType }
                    }
                })
            Write-Event 'HeldServices' (($held | ForEach-Object Name) -join ', ')
        }

        if ($snap.Pending) { Assert-NotStopped; $session = Restart-AndWait $session }

        for ($round = 1; $round -le $Options.MaxRounds; $round++) {
            Assert-NotStopped
            $count = Install-Updates $session
            $pending = (Invoke-Command -Session $session -ScriptBlock $snapshotScript).Pending
            Set-Status "Round $round finished" @{ RebootPending = $pending }
            if (-not $pending) { break }
            Assert-NotStopped
            $session = Restart-AndWait $session
            if ($count -eq 0) { break }
        }

        if ($held) {
            Set-Status 'Starting held services'
            Invoke-Command -Session $session -ArgumentList (, $held) -ScriptBlock {
                param($Held)
                foreach ($h in $Held) { Set-Service -Name $h.Name -StartupType $h.StartType; Start-Service -Name $h.Name -ErrorAction SilentlyContinue }
            }
        }

        if ($state.Reboots -gt 0) {
            Set-Status 'Checking services'
            Start-Sleep -Seconds 120   # give delayed-start services a chance
            $notRunning = @(Invoke-Command -Session $session -ArgumentList (, $servicesBefore) -ScriptBlock {
                    param($Before)
                    foreach ($name in $Before) {
                        $s = Get-Service -Name $name -ErrorAction SilentlyContinue
                        if (-not $s -or $s.Status -eq 'Running') { continue }
                        Start-Service -Name $name -ErrorAction SilentlyContinue
                        Start-Sleep -Seconds 5
                        if ((Get-Service -Name $name).Status -ne 'Running') { $s.DisplayName }
                    }
                })
            $state.ServicesNotStarted = $notRunning -join ', '
        }
        $final = Invoke-Command -Session $session -ScriptBlock $snapshotScript
        $result = if ($state.Failed) { 'FinishedWithErrors' } elseif ($state.ServicesNotStarted) { 'FinishedServicesDown' } else { 'Finished' }
        Set-Status 'Finished' @{ Result = $result; FreeGB = $final.FreeGB; RebootPending = $final.Pending }
    }
    catch [System.OperationCanceledException] { Set-Status 'Stopped' @{ Result = 'Stopped'; Message = $_.Exception.Message } }
    catch {
        $result = if ($state.Stage -eq 'Connecting') { 'ConnectionFailed' } else { 'Failed' }
        Set-Status $state.Stage @{ Result = $result; Message = $_.Exception.Message }
        Write-Event 'Error' $_.Exception.Message
    }
    finally {
        if ($session) { Remove-PSSession -Session $session -ErrorAction SilentlyContinue }
        $state.Finished = (Get-Date).ToString('s')
        Set-Status $state.Stage -NoEvent
        [PSCustomObject]$state
    }
}

#endregion

$options = @{
    WorkFolder = $WorkFolder; Execute = [bool]$Execute; RebootMode = $RebootMode; RebootTimeoutMinutes = $RebootTimeoutMinutes
    InstallTimeoutMinutes = $InstallTimeoutMinutes; MaxRounds = $MaxInstallRounds; HoldPattern = $HoldServicePattern
    IncludeDCs = [bool]$IncludeDomainControllers; ModuleSource = $PSWindowsUpdateSource
}
$rebootSlots = New-Object System.Threading.SemaphoreSlim($MaxParallelReboots, $MaxParallelReboots)
$pool = [runspacefactory]::CreateRunspacePool(1, $ThrottleLimit)
$pool.Open()
$jobs = foreach ($s in $servers) {
    $ps = [powershell]::Create()
    $ps.RunspacePool = $pool
    [void]$ps.AddScript($worker).AddArgument($s).AddArgument($options).AddArgument($Credential).AddArgument($rebootSlots)
    [PSCustomObject]@{ Server = $s; Shell = $ps; Handle = $ps.BeginInvoke() }
}

$deadline = (Get-Date).AddHours($TimeoutHours)
$lastLine = ''
while (($jobs | Where-Object { -not $_.Handle.IsCompleted }) -and (Get-Date) -lt $deadline) {
    Start-Sleep -Seconds 15
    $statuses = @(Get-ChildItem -LiteralPath (Join-Path $WorkFolder 'status') -Filter *.json -ErrorAction SilentlyContinue |
        ForEach-Object { try { Get-Content -LiteralPath $_.FullName -Raw | ConvertFrom-Json } catch { } })
    $done = @($jobs | Where-Object { $_.Handle.IsCompleted }).Count
    $line = '{0:HH:mm:ss} done {1}/{2} | {3}' -f (Get-Date), $done, $jobs.Count,
        (($statuses | Where-Object { -not $_.Result } | Group-Object Stage | ForEach-Object { "$($_.Name): $($_.Count)" }) -join ' | ')
    if ($line.Substring(9) -ne $lastLine) { Write-Host $line; $lastLine = $line.Substring(9) }
}

$results = foreach ($j in $jobs) {
    if ($j.Handle.IsCompleted) {
        try { $j.Shell.EndInvoke($j.Handle) | Select-Object -Last 1 } catch { [PSCustomObject]@{ Server = $j.Server; Result = 'Failed'; Message = $_.Exception.Message } }
    }
    else {
        [void]$j.Shell.BeginStop($null, $null)
        [PSCustomObject]@{ Server = $j.Server; Result = 'Timeout'; Message = "still running after $TimeoutHours h" }
    }
    $j.Shell.Dispose()
}
$pool.Close(); $pool.Dispose()
$results = @($results)
$results | Export-Csv -LiteralPath (Join-Path $WorkFolder 'results\summary.csv') -NoTypeInformation -Encoding UTF8

Write-Host ''
Write-Host ('Results: ' + (($results | Group-Object Result | ForEach-Object { "$($_.Name)=$($_.Count)" }) -join ', ')) -ForegroundColor Cyan
$results | Where-Object { $_.Result -notin 'Finished', 'DryRun', 'Skipped' } |
    Format-Table Server, Result, Stage, Message -AutoSize -Wrap | Out-String -Width 220 | Write-Host
Write-Host "Details: $WorkFolder (status\, logs\, results\summary.csv)" -ForegroundColor DarkGray
$results
