<#
.SYNOPSIS
    Shows the live status of a patching run started with Invoke-ServerPatching.ps1.

.DESCRIPTION
    Reads <WorkFolder>\status\*.json written by the workers and prints one row per server: stage, result,
    connection state, pending reboot, number of reboots, installed and failed updates, free space,
    services that did not start, elapsed time. With -Watch the table refreshes until all servers are finished.

.PARAMETER WorkFolder
    Work folder of the run (PatchRun_<timestamp>).

.PARAMETER Watch
    Refresh continuously.

.PARAMETER RefreshSeconds
    Refresh interval for -Watch. Default: 15.

.PARAMETER GridView
    Show the table in Out-GridView (one snapshot).

.EXAMPLE
    .\Get-PatchingStatus.ps1 -WorkFolder .\PatchRun_20261008_1800 -Watch

.EXAMPLE
    .\Get-PatchingStatus.ps1 -WorkFolder .\PatchRun_20261008_1800 | Where-Object Result -like 'Failed*'
#>
#Requires -Version 5.1
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$WorkFolder,
    [switch]$Watch,
    [ValidateRange(5, 600)][int]$RefreshSeconds = 15,
    [switch]$GridView
)

Set-StrictMode -Version Latest
$statusDir = Join-Path $WorkFolder 'status'
if (-not (Test-Path -LiteralPath $statusDir)) { throw "Not a patching work folder: $WorkFolder" }

function Get-Rows {
    foreach ($f in (Get-ChildItem -LiteralPath $statusDir -Filter *.json)) {
        try { $s = Get-Content -LiteralPath $f.FullName -Raw | ConvertFrom-Json } catch { continue }
        $start = [datetime]$s.Started
        $end = if ($s.Finished) { [datetime]$s.Finished } else { Get-Date }
        [PSCustomObject]@{
            Server    = $s.Server
            Stage     = $s.Stage
            Result    = $s.Result
            Conn      = $s.Connection
            Pending   = $s.RebootPending
            Reboots   = $s.Reboots
            Avail     = $s.Available
            Installed = $s.Installed
            Failed    = $s.Failed
            FreeGB    = $s.FreeGB
            Elapsed   = '{0:hh\:mm}' -f ($end - $start)
            Services  = $s.ServicesNotStarted
            Message   = $s.Message
        }
    }
}

if ($GridView) { Get-Rows | Sort-Object Server | Out-GridView -Title "Patching status - $WorkFolder"; return }
if (-not $Watch) { Get-Rows | Sort-Object Server; return }

do {
    $rows = @(Get-Rows | Sort-Object @{ Expression = { [bool]$_.Result } }, Server)
    Clear-Host
    Write-Host ('Patching status {0:HH:mm:ss}  {1}' -f (Get-Date), $WorkFolder) -ForegroundColor Cyan
    Write-Host ('Finished {0} of {1}: {2}' -f @($rows | Where-Object Result).Count, $rows.Count,
        (($rows | Where-Object Result | Group-Object Result | ForEach-Object { "$($_.Name)=$($_.Count)" }) -join ', '))
    foreach ($r in $rows) {
        $color = switch -Wildcard ($r.Result) {
            'Finished' { 'Green' } 'DryRun' { 'Green' } 'Skipped' { 'DarkGray' } 'Finished*' { 'Yellow' }
            'Failed' { 'Red' } 'ConnectionFailed' { 'Red' } 'Stopped' { 'Yellow' } default { if ($r.Stage -like 'Waiting*') { 'Magenta' } else { 'Gray' } }
        }
        Write-Host ('{0,-22} {1,-38} {2,-18} reboots {3} inst {4,3} fail {5,2} free {6,6} {7}' -f
            $r.Server, ($r.Stage -replace '^(.{38}).+$', '$1'), $r.Result, $r.Reboots, $r.Installed, $r.Failed, $r.FreeGB, $r.Elapsed) -ForegroundColor $color
        if ($r.Services) { Write-Host ('{0,-22} services not started: {1}' -f '', $r.Services) -ForegroundColor Red }
        if ($r.Message -and $r.Result -notin 'Finished', 'DryRun') { Write-Host ('{0,-22} {1}' -f '', $r.Message) -ForegroundColor DarkGray }
    }
    if (@($rows | Where-Object { -not $_.Result }).Count -eq 0 -and $rows) { break }
    Start-Sleep -Seconds $RefreshSeconds
} while ($true)
