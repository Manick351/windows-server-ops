<#
.SYNOPSIS
    Frees disk space on remote Windows servers: user and browser caches, temp files, dumps, logs,
    Windows Update cache and the component store. Dry run by default.

.DESCRIPTION
    Runs on any number of servers in parallel over WinRM. Five stages on every server:

      1. User caches in every profile: Edge/Chrome/Firefox caches (skipped for a user whose browser
         is running), RDP client cache, profile temp, crash dumps, WER; Office/Teams/VS Code caches,
         INetCache and thumbnails only for profiles that are not loaded.
      2. System temp, LiveKernelReports, memory dumps, WER, archived event logs, CBS/DISM logs
         (current CBS.log and dism.log kept), setup logs, diagnostic ETL logs, IIS logs; optionally the recycle bin.
      3. Windows Update download cache and Delivery Optimization (services are stopped and started again).
      4. Component store: skipped when a reboot is pending; otherwise DISM /AnalyzeComponentStore and,
         if cleanup is recommended, /StartComponentCleanup (with -ResetBase only when asked: it makes
         installed updates impossible to uninstall).
      5. Diagnostics only (never deleted): active event logs, search index, Windows\Installer,
         OS upgrade leftovers, SCCM cache, package manager caches, profiles unused for 90 days.

    Files younger than -RetentionDays are kept where age matters (temp, dumps, logs).
    Without -Execute nothing is deleted and no service is stopped: the report shows what would be freed.

.PARAMETER ComputerName
    Servers to clean. Accepts pipeline input.

.PARAMETER Credential
    Optional credential for WinRM.

.PARAMETER RetentionDays
    Minimum age of temp files, dumps and logs to delete. Default: 14.

.PARAMETER Execute
    Delete files and run DISM. Without it the script only analyzes.

.PARAMETER ResetBase
    Add /ResetBase to DISM component cleanup (frees more, but updates can no longer be uninstalled).

.PARAMETER IncludeRecycleBin
    Empty recycle bins (files older than -RetentionDays).

.PARAMETER ThrottleLimit
    Servers processed in parallel. Default: 8.

.PARAMETER LogPath
    Folder for the per-server text reports.

.EXAMPLE
    .\Clear-ServerDisk.ps1 -ComputerName srv-app-01, srv-app-02

    Dry run: shows what can be freed on each server.

.EXAMPLE
    Get-Content .\servers.txt | .\Clear-ServerDisk.ps1 -Execute -RetentionDays 7
#>
#Requires -Version 5.1
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
    [Alias('Name')]
    [string[]]$ComputerName,

    [pscredential]$Credential,

    [ValidateRange(0, 3650)]
    [int]$RetentionDays = 14,

    [switch]$Execute,

    [switch]$ResetBase,

    [switch]$IncludeRecycleBin,

    [ValidateRange(1, 64)]
    [int]$ThrottleLimit = 8,

    [string]$LogPath = (Join-Path $env:ProgramData 'windows-server-ops\logs')
)

begin {
    Set-StrictMode -Version Latest
    $targets = New-Object System.Collections.Generic.List[string]

    $remote = {
        param([bool]$Execute, [int]$Retention, [bool]$ResetBase, [bool]$RecycleBin)
        $ErrorActionPreference = 'Continue'
        $win = $env:windir
        $pd = $env:ProgramData

        function Get-PathSize {
            param([string]$Path)
            $sum = [long]0
            foreach ($item in @(Get-Item -Path $Path -Force -ErrorAction SilentlyContinue)) {
                if ($item.PSIsContainer) {
                    $s = (Get-ChildItem -LiteralPath $item.FullName -Recurse -File -Force -ErrorAction SilentlyContinue | Measure-Object Length -Sum).Sum
                    if ($s) { $sum += $s }
                }
                else { $sum += $item.Length }
            }
            return $sum
        }

        function Invoke-Target {
            # Deletes files under -Paths (wildcards allowed) older than -MinAgeDays; returns found/freed bytes.
            param([string]$Name, [string]$Group, [string[]]$Paths, [int]$MinAgeDays = 0, [string[]]$Keep = @(), [string]$Note = '')
            $found = [long]0; $freed = [long]0; $failed = 0
            $cutoff = (Get-Date).AddDays(-$MinAgeDays)
            foreach ($p in $Paths) {
                foreach ($item in @(Get-Item -Path $p -Force -ErrorAction SilentlyContinue)) {
                    $files = if ($item.PSIsContainer) { @(Get-ChildItem -LiteralPath $item.FullName -Recurse -File -Force -ErrorAction SilentlyContinue) } else { @($item) }
                    foreach ($f in $files) {
                        if ($MinAgeDays -gt 0 -and $f.LastWriteTime -ge $cutoff) { continue }
                        if ($Keep -contains $f.Name) { continue }
                        $found += $f.Length
                        if (-not $Execute) { continue }
                        $len = $f.Length
                        Remove-Item -LiteralPath $f.FullName -Force -ErrorAction SilentlyContinue
                        if (Test-Path -LiteralPath $f.FullName) { $failed++ } else { $freed += $len }
                    }
                }
            }
            [PSCustomObject]@{ Name = $Name; Group = $Group; FoundBytes = $found; FreedBytes = $freed; Locked = $failed; Note = $Note }
        }

        function Invoke-Dism {
            param([string]$Arguments)
            $out = Join-Path $env:TEMP ('dism_' + [guid]::NewGuid().ToString('N') + '.txt')
            $p = Start-Process -FilePath "$win\System32\Dism.exe" -ArgumentList $Arguments -Wait -PassThru -NoNewWindow -RedirectStandardOutput $out
            $text = Get-Content -LiteralPath $out -Raw -ErrorAction SilentlyContinue
            Remove-Item -LiteralPath $out -Force -ErrorAction SilentlyContinue
            [PSCustomObject]@{ Code = $p.ExitCode; Text = $text }
        }

        $disks = { Get-CimInstance Win32_LogicalDisk -Filter 'DriveType=3' | ForEach-Object { [PSCustomObject]@{ Drive = $_.DeviceID; SizeGB = [Math]::Round($_.Size / 1GB, 1); FreeGB = [Math]::Round($_.FreeSpace / 1GB, 2) } } }
        $result = [ordered]@{
            Server = $env:COMPUTERNAME; OS = (Get-CimInstance Win32_OperatingSystem).Caption; Started = Get-Date
            DisksBefore = @(& $disks); DisksAfter = @(); Targets = @(); Dism = $null; Diagnostics = @(); Error = $null
        }
        try {
            $profiles = @(Get-CimInstance Win32_UserProfile | Where-Object { -not $_.Special -and $_.LocalPath -and $_.SID -like 'S-1-5-21-*' -and (Test-Path -LiteralPath $_.LocalPath) })
            $browsers = @{}
            foreach ($proc in @(Get-CimInstance Win32_Process -Filter "Name='chrome.exe' OR Name='msedge.exe' OR Name='firefox.exe'")) {
                $owner = ($proc | Invoke-CimMethod -MethodName GetOwnerSid -ErrorAction SilentlyContinue).Sid
                if ($owner) { $browsers["$owner|$($proc.Name)"] = $true }
            }

            # 1. User caches
            $userTargets = @(
                @{ N = 'Edge cache'; R = 'AppData\Local\Microsoft\Edge\User Data\*\Cache', 'AppData\Local\Microsoft\Edge\User Data\*\Code Cache', 'AppData\Local\Microsoft\Edge\User Data\*\GPUCache'; Age = 0; Proc = 'msedge.exe'; Idle = $false }
                @{ N = 'Chrome cache'; R = 'AppData\Local\Google\Chrome\User Data\*\Cache', 'AppData\Local\Google\Chrome\User Data\*\Code Cache', 'AppData\Local\Google\Chrome\User Data\*\GPUCache'; Age = 0; Proc = 'chrome.exe'; Idle = $false }
                @{ N = 'Firefox cache'; R = 'AppData\Local\Mozilla\Firefox\Profiles\*\cache2', 'AppData\Local\Mozilla\Firefox\Profiles\*\startupCache'; Age = 0; Proc = 'firefox.exe'; Idle = $false }
                @{ N = 'RDP client cache'; R = 'AppData\Local\Microsoft\Terminal Server Client\Cache'; Age = 0; Proc = ''; Idle = $false }
                @{ N = 'Profile temp'; R = 'AppData\Local\Temp'; Age = $Retention; Proc = ''; Idle = $false }
                @{ N = 'Application crash dumps'; R = 'AppData\Local\CrashDumps'; Age = $Retention; Proc = ''; Idle = $false }
                @{ N = 'User WER reports'; R = 'AppData\Local\Microsoft\Windows\WER\ReportQueue', 'AppData\Local\Microsoft\Windows\WER\ReportArchive'; Age = $Retention; Proc = ''; Idle = $false }
                @{ N = 'INetCache'; R = 'AppData\Local\Microsoft\Windows\INetCache\IE', 'AppData\Local\Microsoft\Windows\INetCache\Low'; Age = 0; Proc = ''; Idle = $true }
                @{ N = 'Thumbnail and icon cache'; R = 'AppData\Local\Microsoft\Windows\Explorer\thumbcache_*.db', 'AppData\Local\Microsoft\Windows\Explorer\iconcache_*.db'; Age = 0; Proc = ''; Idle = $true }
                @{ N = 'Office cache'; R = 'AppData\Local\Microsoft\Office\*\OfficeFileCache', 'AppData\Local\Microsoft\Office\*\WebServiceCache'; Age = 0; Proc = ''; Idle = $true }
                @{ N = 'Teams cache'; R = 'AppData\Roaming\Microsoft\Teams\Cache', 'AppData\Roaming\Microsoft\Teams\Code Cache', 'AppData\Roaming\Microsoft\Teams\GPUCache', 'AppData\Local\Packages\MSTeams_*\LocalCache\Microsoft\MSTeams\*Cache*'; Age = 0; Proc = ''; Idle = $true }
                @{ N = 'VS Code cache'; R = 'AppData\Roaming\Code\Cache', 'AppData\Roaming\Code\CachedData', 'AppData\Roaming\Code\Code Cache', 'AppData\Roaming\Code\logs'; Age = 0; Proc = ''; Idle = $true }
            )
            foreach ($t in $userTargets) {
                $paths = @(); $skipped = 0
                foreach ($prof in $profiles) {
                    if (($t.Idle -and $prof.Loaded) -or ($t.Proc -and $browsers.ContainsKey("$($prof.SID)|$($t.Proc)"))) { $skipped++; continue }
                    foreach ($rel in $t.R) { $paths += Join-Path $prof.LocalPath $rel }
                }
                $note = if ($skipped) { "skipped $skipped profile(s) in use" } else { '' }
                $result.Targets += Invoke-Target -Name $t.N -Group 'Users' -Paths $paths -MinAgeDays $t.Age -Note $note
            }

            # 2. System temp and logs
            $systemTargets = @(
                @{ N = 'Windows\Temp'; P = "$win\Temp"; Age = 1; Keep = @() }
                @{ N = 'LiveKernelReports'; P = "$win\LiveKernelReports"; Age = $Retention; Keep = @() }
                @{ N = 'Memory dumps'; P = "$win\MEMORY.DMP", "$win\Minidump"; Age = $Retention; Keep = @() }
                @{ N = 'System WER reports'; P = "$pd\Microsoft\Windows\WER\ReportQueue", "$pd\Microsoft\Windows\WER\ReportArchive", "$pd\Microsoft\Windows\WER\Temp"; Age = $Retention; Keep = @() }
                @{ N = 'Archived event logs'; P = "$win\System32\winevt\Logs\Archive-*.evtx"; Age = $Retention; Keep = @() }
                @{ N = 'CBS and DISM logs'; P = "$win\Logs\CBS", "$win\Logs\DISM"; Age = $Retention; Keep = @('CBS.log', 'dism.log') }
                @{ N = 'Setup and update logs'; P = "$win\Logs\MoSetup", "$win\Logs\WindowsUpdate", "$win\Panther", "$win\inf\setupapi.dev.*.log"; Age = 30; Keep = @() }
                @{ N = 'Diagnostic ETL logs'; P = "$pd\Microsoft\Diagnosis\ETLLogs"; Age = 30; Keep = @() }
                @{ N = 'IIS logs'; P = "$env:SystemDrive\inetpub\logs\LogFiles"; Age = 30; Keep = @() }
            )
            foreach ($t in $systemTargets) { $result.Targets += Invoke-Target -Name $t.N -Group 'System' -Paths $t.P -MinAgeDays $t.Age -Keep $t.Keep }
            if ($RecycleBin) {
                $bins = @($result.DisksBefore | ForEach-Object { "$($_.Drive)\`$Recycle.Bin" })
                $result.Targets += Invoke-Target -Name 'Recycle bins' -Group 'System' -Paths $bins -MinAgeDays $Retention
            }

            # 3. Windows Update cache (services must be stopped to release the files)
            $stopped = @()
            if ($Execute) {
                foreach ($svc in 'wuauserv', 'bits', 'dosvc') {
                    $s = Get-Service -Name $svc -ErrorAction SilentlyContinue
                    if ($s -and $s.Status -eq 'Running') { Stop-Service -Name $svc -Force -ErrorAction SilentlyContinue; $stopped += $svc }
                }
            }
            $result.Targets += Invoke-Target -Name 'Windows Update downloads' -Group 'Updates' -Paths "$win\SoftwareDistribution\Download"
            $result.Targets += Invoke-Target -Name 'Delivery Optimization' -Group 'Updates' -Paths "$win\SoftwareDistribution\DeliveryOptimization"
            $notStarted = @()
            foreach ($svc in $stopped) {
                Start-Service -Name $svc -ErrorAction SilentlyContinue
                if ((Get-Service -Name $svc).Status -ne 'Running') { $notStarted += $svc }
            }

            # 4. Component store
            $cbs = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing'
            $blockers = @()
            if (Test-Path "$cbs\RebootPending") { $blockers += 'CBS RebootPending' }
            if (Test-Path "$cbs\PackagesPending") { $blockers += 'CBS PackagesPending' }
            if (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired') { $blockers += 'Windows Update RebootRequired' }
            $dism = [ordered]@{ Blocked = ($blockers -join ', '); StoreSize = ''; Recommended = $null; Executed = $false; ExitCode = $null; Minutes = 0; ServicesNotStarted = ($notStarted -join ', ') }
            if (-not $blockers) {
                $analyze = Invoke-Dism '/Online /Cleanup-Image /AnalyzeComponentStore /English'
                if ($analyze.Text -match '(?im)^\s*Actual Size of Component Store\s*:\s*(.+?)\s*$') { $dism.StoreSize = $Matches[1] }
                if ($analyze.Text -match '(?im)^\s*Component Store Cleanup Recommended\s*:\s*(\S+)') { $dism.Recommended = ($Matches[1] -eq 'Yes') }
                if ($Execute -and $dism.Recommended -ne $false) {
                    $t0 = Get-Date
                    $cleanup = Invoke-Dism ('/Online /Cleanup-Image /StartComponentCleanup /Quiet' + $(if ($ResetBase) { ' /ResetBase' } else { '' }))
                    $dism.Executed = $true
                    $dism.ExitCode = $cleanup.Code
                    $dism.Minutes = [Math]::Round(((Get-Date) - $t0).TotalMinutes, 1)
                }
            }
            $result.Dism = [PSCustomObject]$dism

            # 5. Diagnostics (reported, never deleted)
            $diag = @()
            $logs = @(Get-ChildItem -LiteralPath "$win\System32\winevt\Logs" -Filter *.evtx -Force -ErrorAction SilentlyContinue | Where-Object { $_.Name -notlike 'Archive-*' })
            $top = ($logs | Sort-Object Length -Descending | Select-Object -First 3 | ForEach-Object { '{0} {1:N0} MB' -f $_.BaseName, ($_.Length / 1MB) }) -join ', '
            $diag += [PSCustomObject]@{ Name = 'Active event logs'; Bytes = [long]($logs | Measure-Object Length -Sum).Sum; Hint = "largest: $top (limited by log MaxSize)" }
            $edb = "$pd\Microsoft\Search\Data\Applications\Windows\Windows.edb"
            if (Test-Path -LiteralPath $edb) { $diag += [PSCustomObject]@{ Name = 'Windows Search index'; Bytes = (Get-Item -LiteralPath $edb).Length; Hint = 'rebuild by resetting the WSearch service index' } }
            $diag += [PSCustomObject]@{ Name = 'Windows\Installer'; Bytes = Get-PathSize "$win\Installer"; Hint = 'do not delete manually: breaks repair and uninstall' }
            foreach ($l in 'Windows.old', '$Windows.~BT', '$Windows.~WS') {
                $p = Join-Path $env:SystemDrive $l
                if (Test-Path -LiteralPath $p) { $diag += [PSCustomObject]@{ Name = "OS upgrade leftover: $l"; Bytes = Get-PathSize $p; Hint = 'remove with Disk Cleanup (cleanmgr)' } }
            }
            if (Test-Path -LiteralPath "$win\ccmcache") { $diag += [PSCustomObject]@{ Name = 'SCCM client cache'; Bytes = Get-PathSize "$win\ccmcache"; Hint = 'clean via the ConfigMgr client, not by hand' } }
            $devBytes = [long]0
            foreach ($prof in $profiles) {
                foreach ($rel in 'go\pkg\mod', 'AppData\Roaming\npm-cache', 'AppData\Local\pip\Cache', 'AppData\Local\NuGet\Cache', 'AppData\Local\Yarn\Cache') {
                    $p = Join-Path $prof.LocalPath $rel
                    if (Test-Path -LiteralPath $p) { $devBytes += Get-PathSize $p }
                }
            }
            if ($devBytes) { $diag += [PSCustomObject]@{ Name = 'Package manager caches'; Bytes = $devBytes; Hint = 'go clean -modcache, npm cache clean --force, pip cache purge' } }
            $unused = @($profiles | Where-Object { $_.LastUseTime -and -not $_.Loaded -and $_.LastUseTime -lt (Get-Date).AddDays(-90) })
            if ($unused) { $diag += [PSCustomObject]@{ Name = "Profiles unused for 90+ days: $($unused.Count)"; Bytes = 0; Hint = (($unused | Select-Object -First 8 | ForEach-Object { Split-Path $_.LocalPath -Leaf }) -join ', ') } }
            $result.Diagnostics = $diag
        }
        catch { $result.Error = $_.Exception.Message }
        $result.DisksAfter = @(& $disks)
        $result.Finished = Get-Date
        [PSCustomObject]$result
    }

    function Format-Size {
        param([double]$Bytes)
        if ($Bytes -ge 1GB) { return '{0:N2} GB' -f ($Bytes / 1GB) }
        if ($Bytes -ge 1MB) { return '{0:N0} MB' -f ($Bytes / 1MB) }
        return '{0:N0} KB' -f ($Bytes / 1KB)
    }
}

process { foreach ($c in $ComputerName) { if ($c) { $targets.Add($c.Trim()) } } }

end {
    if (-not (Test-Path -LiteralPath $LogPath)) { New-Item -ItemType Directory -Path $LogPath -Force | Out-Null }
    $mode = if ($Execute) { 'EXECUTE' } else { 'DRY RUN' }
    Write-Host ("Cleanup on {0} server(s), mode {1}, retention {2} days, ResetBase {3}" -f $targets.Count, $mode, $RetentionDays, [bool]$ResetBase) -ForegroundColor $(if ($Execute) { 'Yellow' } else { 'Green' })

    $params = @{
        ComputerName  = @($targets | Sort-Object -Unique)
        ScriptBlock   = $remote
        ArgumentList  = [bool]$Execute, $RetentionDays, [bool]$ResetBase, [bool]$IncludeRecycleBin
        ThrottleLimit = $ThrottleLimit
        SessionOption = New-PSSessionOption -OperationTimeout (2 * 3600 * 1000) -IdleTimeout (2 * 3600 * 1000)
        ErrorAction   = 'SilentlyContinue'
        ErrorVariable = 'remoteErrors'
    }
    if ($Credential) { $params.Credential = $Credential }
    $results = @(Invoke-Command @params)

    foreach ($r in $results) {
        $lines = New-Object System.Collections.Generic.List[string]
        $lines.Add(('=' * 80))
        $lines.Add("$($r.Server)  |  $($r.OS)  |  $mode  |  {0:yyyy-MM-dd HH:mm} - {1:HH:mm}" -f $r.Started, $r.Finished)
        if ($r.Error) { $lines.Add("ERROR: $($r.Error)") }
        foreach ($group in 'Users', 'System', 'Updates') {
            $items = @($r.Targets | Where-Object { $_.Group -eq $group -and ($_.FoundBytes -gt 0 -or $_.Note) })
            if (-not $items) { continue }
            $lines.Add("  [$group]")
            foreach ($t in $items) {
                $amount = if ($Execute) { 'freed {0} of {1}' -f (Format-Size $t.FreedBytes), (Format-Size $t.FoundBytes) } else { 'found {0}' -f (Format-Size $t.FoundBytes) }
                $extra = @()
                if ($t.Locked) { $extra += "$($t.Locked) locked" }
                if ($t.Note) { $extra += $t.Note }
                $lines.Add(('    {0,-30} {1}{2}' -f $t.Name, $amount, $(if ($extra) { '  (' + ($extra -join '; ') + ')' } else { '' })))
            }
        }
        $found = ($r.Targets | Measure-Object FoundBytes -Sum).Sum
        $freed = ($r.Targets | Measure-Object FreedBytes -Sum).Sum
        $lines.Add($(if ($Execute) { "  TOTAL freed: $(Format-Size $freed) of $(Format-Size $found)" } else { "  TOTAL can be freed: $(Format-Size $found)" }))
        $d = $r.Dism
        if ($d) {
            if ($d.Blocked) { $lines.Add("  Component store: skipped, reboot pending ($($d.Blocked))") }
            elseif ($d.Recommended -eq $false) { $lines.Add("  Component store: $($d.StoreSize), cleanup not recommended") }
            elseif ($d.Executed) { $lines.Add("  Component store: $($d.StoreSize), cleanup exit code $($d.ExitCode) in $($d.Minutes) min") }
            else { $lines.Add("  Component store: $($d.StoreSize), cleanup recommended (run with -Execute)") }
            if ($d.ServicesNotStarted) { $lines.Add("  WARNING: services did not start again: $($d.ServicesNotStarted)") }
        }
        foreach ($x in $r.Diagnostics) { $lines.Add(('  diag: {0}{1} - {2}' -f $x.Name, $(if ($x.Bytes) { ': ' + (Format-Size $x.Bytes) } else { '' }), $x.Hint)) }
        foreach ($b in $r.DisksBefore) {
            $a = $r.DisksAfter | Where-Object Drive -eq $b.Drive
            $lines.Add(('  {0} free {1} GB -> {2} GB of {3} GB' -f $b.Drive, $b.FreeGB, $(if ($a) { $a.FreeGB } else { '?' }), $b.SizeGB))
        }
        $lines | ForEach-Object { Write-Host $_ }
        $lines | Out-File -LiteralPath (Join-Path $LogPath ('ServerCleanup_{0}_{1:yyyyMMdd_HHmm}_{2}.txt' -f $r.Server, (Get-Date), $(if ($Execute) { 'EXEC' } else { 'DRY' }))) -Encoding UTF8

        [PSCustomObject]@{
            Server     = $r.Server
            FoundGB    = [Math]::Round($found / 1GB, 2)
            FreedGB    = [Math]::Round($freed / 1GB, 2)
            DismResult = if (-not $d) { '' } elseif ($d.Blocked) { 'reboot pending' } elseif ($d.Executed) { "exit $($d.ExitCode)" } elseif ($d.Recommended) { 'recommended' } else { 'not needed' }
            Error      = $r.Error
        }
    }
    foreach ($e in $remoteErrors) {
        Write-Warning ("{0}: {1}" -f $(if ($e.TargetObject) { $e.TargetObject } else { 'unknown' }), $e.Exception.Message)
    }
    if (-not $Execute) { Write-Host 'Dry run: nothing was deleted. Add -Execute to clean.' -ForegroundColor Yellow }
}
