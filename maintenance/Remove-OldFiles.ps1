<#
.SYNOPSIS
    Deletes files older than a retention period from configured folders (exchange, archive, export folders).
    Dry run by default; designed for a scheduled task.

.DESCRIPTION
    Integration folders (ERP exports, EDI archives, processed queues) grow forever unless something
    deletes old files. Targets are described in a .psd1 file: path, retention days, file mask, recursion,
    and whether to remove empty subfolders.

    Safety guards:
      - every target must be inside AllowedRoot from the configuration;
      - paths shallower than MinPathDepth (default 3, e.g. D:\Exchange\Archive) are refused;
      - files are enumerated lazily, long paths (\\?\) and read-only files are handled;
      - the first 20 errors per target are logged, the rest are counted.

    Exit code: 0 if no errors, 1 otherwise (useful for task scheduler alerting).

.PARAMETER ConfigPath
    .psd1 file with AllowedRoot, MinPathDepth, LogPath and Targets. See examples\cleanup-targets.example.psd1.

.PARAMETER Execute
    Actually delete. Without it the script only counts what would be deleted.

.PARAMETER LogRetentionDays
    Delete own log files older than this. Default: 90.

.EXAMPLE
    .\Remove-OldFiles.ps1 -ConfigPath .\cleanup-targets.psd1

.EXAMPLE
    powershell.exe -NoProfile -File .\Remove-OldFiles.ps1 -ConfigPath D:\Scripts\cleanup-targets.psd1 -Execute
#>
#Requires -Version 5.1
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$ConfigPath,

    [switch]$Execute,

    [ValidateRange(0, 3650)]
    [int]$LogRetentionDays = 90
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$config = Import-PowerShellDataFile -LiteralPath $ConfigPath
foreach ($k in 'AllowedRoot', 'Targets') { if (-not $config.ContainsKey($k)) { throw "'$k' is missing in $ConfigPath." } }
$allowedRoot = [IO.Path]::GetFullPath($config.AllowedRoot).TrimEnd('\')
$minDepth = if ($config.ContainsKey('MinPathDepth')) { [int]$config.MinPathDepth } else { 3 }
$logDir = if ($config.ContainsKey('LogPath')) { $config.LogPath } else { Join-Path $env:ProgramData 'windows-server-ops\logs' }
$scriptName = 'Remove-OldFiles'

if (-not (Test-Path -LiteralPath $logDir)) { New-Item -ItemType Directory -Path $logDir -Force | Out-Null }
$logFile = Join-Path $logDir ('{0}_{1:yyyy-MM-dd}.log' -f $scriptName, (Get-Date))

function Write-Log {
    param([string]$Message, [string]$Level = 'INFO')
    $line = '[{0:yyyy-MM-dd HH:mm:ss}] [{1}] {2}' -f (Get-Date), $Level, $Message
    Write-Host $line -ForegroundColor $(switch ($Level) { 'ERROR' { 'Red' } 'WARN' { 'Yellow' } default { 'Gray' } })
    for ($i = 0; $i -lt 5; $i++) {
        try { [IO.File]::AppendAllText($logFile, $line + [Environment]::NewLine, [Text.Encoding]::UTF8); break }
        catch { Start-Sleep -Milliseconds 200 }
    }
}

function Test-TargetSafety {
    param([string]$Path)
    $full = [IO.Path]::GetFullPath($Path).TrimEnd('\')
    if (-not ($full.Equals($allowedRoot, [StringComparison]::OrdinalIgnoreCase) -or
            $full.StartsWith($allowedRoot + '\', [StringComparison]::OrdinalIgnoreCase))) {
        Write-Log "BLOCKED: $full is outside AllowedRoot $allowedRoot" 'ERROR'
        return $false
    }
    $depth = @($full -split '\\' | Where-Object { $_ }).Count
    if ($depth -lt $minDepth) {
        Write-Log "BLOCKED: $full is too shallow (depth $depth, minimum $minDepth)" 'ERROR'
        return $false
    }
    return $true
}

function Remove-EmptyDirectories {
    param([string]$Root, [bool]$DoDelete)
    $removed = 0
    try {
        $dirs = [IO.Directory]::EnumerateDirectories($Root, '*', [IO.SearchOption]::AllDirectories) | Sort-Object Length -Descending
    }
    catch { Write-Log "Cannot enumerate subfolders of $Root : $($_.Exception.Message)" 'WARN'; return 0 }
    foreach ($d in $dirs) {
        try {
            if ([IO.Directory]::EnumerateFileSystemEntries($d) | Select-Object -First 1) { continue }
            if ($DoDelete) { [IO.Directory]::Delete($d, $false) }
            $removed++
        }
        catch { Write-Log "Empty folder not removed: $d : $($_.Exception.Message)" 'WARN' }
    }
    return $removed
}

function Invoke-TargetCleanup {
    param([hashtable]$Target, [bool]$DoDelete)
    $path = $Target.Path
    $days = [int]$Target.Days
    $mask = if ($Target.ContainsKey('Filter') -and $Target.Filter) { $Target.Filter } else { '*' }
    $recurse = $Target.ContainsKey('Recurse') -and $Target.Recurse
    $option = if ($recurse) { [IO.SearchOption]::AllDirectories } else { [IO.SearchOption]::TopDirectoryOnly }
    $r = [ordered]@{ Path = $path; Days = $days; Scanned = 0; Matched = 0; Deleted = 0; FreedBytes = [long]0; Errors = 0; DirsRemoved = 0; Status = 'OK' }

    Write-Log "--- $path (keep $days days, mask '$mask', recurse $recurse)"
    if (-not (Test-TargetSafety $path)) { $r.Status = 'BLOCKED'; $r.Errors++; return [PSCustomObject]$r }
    if (-not (Test-Path -LiteralPath $path -PathType Container)) { Write-Log "Folder not found: $path" 'WARN'; $r.Status = 'NOTFOUND'; $r.Errors++; return [PSCustomObject]$r }

    $cutoff = (Get-Date).Date.AddDays(-$days)
    try {
        foreach ($f in [IO.Directory]::EnumerateFiles($path, $mask, $option)) {
            $r.Scanned++
            try {
                $info = New-Object IO.FileInfo($f)
                if (-not $info.Exists -or $info.LastWriteTime -ge $cutoff) { continue }
                $r.Matched++
                $size = $info.Length
                if ($DoDelete) {
                    $long = if ($f.StartsWith('\\?\')) { $f } elseif ($f.StartsWith('\\')) { '\\?\UNC\' + $f.Substring(2) } else { '\\?\' + $f }
                    if ($info.Attributes -band [IO.FileAttributes]::ReadOnly) { [IO.File]::SetAttributes($long, [IO.FileAttributes]::Normal) }
                    [IO.File]::Delete($long)
                }
                $r.Deleted++
                $r.FreedBytes += $size
            }
            catch {
                $r.Errors++
                if ($r.Errors -le 20) { Write-Log "Not deleted: $f : $($_.Exception.Message)" 'WARN' }
            }
        }
    }
    catch { Write-Log "Enumeration stopped: $($_.Exception.Message)" 'ERROR'; $r.Errors++; $r.Status = 'ERROR' }

    if ($recurse -and $Target.ContainsKey('RemoveEmptyDirs') -and $Target.RemoveEmptyDirs) {
        $r.DirsRemoved = Remove-EmptyDirectories -Root $path -DoDelete $DoDelete
    }
    if ($r.Errors -and $r.Status -eq 'OK') { $r.Status = 'WARN' }
    Write-Log ('scanned {0}, matched {1}, {2} {3} ({4:N2} MB), empty folders {5}, errors {6}' -f $r.Scanned, $r.Matched,
        $(if ($DoDelete) { 'deleted' } else { 'would delete' }), $r.Deleted, ($r.FreedBytes / 1MB), $r.DirsRemoved, $r.Errors)
    return [PSCustomObject]$r
}

$sw = [Diagnostics.Stopwatch]::StartNew()
Write-Log ('=' * 60)
Write-Log ("{0} | mode {1} | {2} | {3}\{4}" -f $scriptName, $(if ($Execute) { 'EXECUTE' } else { 'DRY RUN' }), $env:COMPUTERNAME, $env:USERDOMAIN, $env:USERNAME)
if (-not $Execute) { Write-Log 'DRY RUN: nothing is deleted. Add -Execute to delete.' 'WARN' }

$results = @(foreach ($t in $config.Targets) { Invoke-TargetCleanup -Target $t -DoDelete $Execute.IsPresent })
$sw.Stop()

$totalDeleted = [long]($results | Measure-Object Deleted -Sum).Sum
$totalFreed = [long]($results | Measure-Object FreedBytes -Sum).Sum
$totalErrors = [long]($results | Measure-Object Errors -Sum).Sum
Write-Log ('-' * 60)
foreach ($r in $results) { Write-Log ('{0,-9} | {1,8} file(s) | {2,10:N2} MB | {3}' -f $r.Status, $r.Deleted, ($r.FreedBytes / 1MB), $r.Path) }
Write-Log ('TOTAL: {0} file(s), {1:N3} GB, {2} error(s), {3:hh\:mm\:ss}' -f $totalDeleted, ($totalFreed / 1GB), $totalErrors, $sw.Elapsed)

if ($LogRetentionDays -gt 0) {
    Get-ChildItem -LiteralPath $logDir -Filter "$scriptName`_*.log" -File -ErrorAction SilentlyContinue |
        Where-Object { $_.LastWriteTime -lt (Get-Date).AddDays(-$LogRetentionDays) } | Remove-Item -Force -ErrorAction SilentlyContinue
}

$results
if ($totalErrors) { exit 1 }
