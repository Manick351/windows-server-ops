<#
.SYNOPSIS
    Cleans up broken local user profiles on a Windows server and restores a profile from a backup folder.
    Dry run by default.

.DESCRIPTION
    Three independent actions:

    -FixRegistry   ProfileList entries (domain SIDs) whose ProfileImagePath no longer exists are removed.
                   Users with a loaded hive or an active session, and -ExcludeUser, are skipped.

    -CleanFolders  Folders in C:\Users without a ProfileList entry are removed (or moved to -QuarantinePath).
                   By default only typical leftovers are touched: TEMP*, *.000, *.DOMAIN, *.BACKUP-n.
                   -IncludePlainOrphans adds any orphan folder; -FolderAgeMonths protects recent ones.
                   -Audit counts files in Desktop/Documents/Downloads/... before you decide.

    -RestoreUser   Puts a user's old profile folder back: renames -FromFolder to C:\Users\<user>,
                   removes the TEMP entry, restores SID.bak to SID, sets ProfileImagePath, State=0, RefCount=0.

    Every ProfileList key is exported to a .reg file before it is changed. Without -Execute only the
    plan is shown. If no action is given, -FixRegistry and -CleanFolders are planned.

.PARAMETER FixRegistry
    Remove dangling ProfileList entries.

.PARAMETER CleanFolders
    Remove orphan profile folders.

.PARAMETER FolderAgeMonths
    Do not touch folders modified within this many months. Default: 6. 0 disables the check.

.PARAMETER IncludePlainOrphans
    Also handle orphan folders without a leftover-like name.

.PARAMETER Audit
    Count user data in candidate folders (slow on large folders).

.PARAMETER QuarantinePath
    Move folders here instead of deleting them.

.PARAMETER RestoreUser
    User whose profile should be restored from -FromFolder.

.PARAMETER FromFolder
    Folder name in C:\Users to restore from, for example jdoe.CONTOSO.000.

.PARAMETER RemoveTempFolder
    With -RestoreUser: delete the TEMP folder the user was given.

.PARAMETER ExcludeUser
    Users to skip.

.PARAMETER Domain
    NetBIOS domain name used to recognize user.DOMAIN folders. Default: current user's domain.

.PARAMETER Execute
    Apply the plan.

.EXAMPLE
    .\Repair-LocalProfile.ps1 -Audit

.EXAMPLE
    .\Repair-LocalProfile.ps1 -CleanFolders -FolderAgeMonths 3 -QuarantinePath D:\ProfileQuarantine -Execute

.EXAMPLE
    .\Repair-LocalProfile.ps1 -RestoreUser jdoe -FromFolder jdoe.CONTOSO.000 -RemoveTempFolder -Execute
#>
#Requires -Version 5.1
#Requires -RunAsAdministrator
[CmdletBinding()]
param(
    [switch]$FixRegistry,
    [switch]$CleanFolders,
    [ValidateRange(0, 120)][int]$FolderAgeMonths = 6,
    [switch]$IncludePlainOrphans,
    [switch]$Audit,
    [string]$QuarantinePath,
    [string]$RestoreUser,
    [string]$FromFolder,
    [switch]$RemoveTempFolder,
    [string[]]$ExcludeUser = @(),
    [string]$Domain = $env:USERDOMAIN,
    [switch]$Execute,
    [string]$LogPath = (Join-Path $env:ProgramData 'windows-server-ops\logs')
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$profileListPs = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList'
$profileListReg = 'HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList'
$usersRoot = Join-Path $env:SystemDrive 'Users'
$protectedFolders = 'Public', 'Default', 'Default User', 'All Users', 'UvhdCleanupBin', 'Administrator', 'defaultuser0'
$stamp = Get-Date -Format 'yyyyMMdd_HHmmss'
$backupDir = Join-Path $LogPath "ProfileList_backup_$($env:COMPUTERNAME)_$stamp"
if (-not (Test-Path -LiteralPath $LogPath)) { New-Item -ItemType Directory -Path $LogPath -Force | Out-Null }
Start-Transcript -Path (Join-Path $LogPath "ProfileRepair_$($env:COMPUTERNAME)_$stamp.log") | Out-Null

function Get-Short { param([string]$Account) ($Account -split '\\')[-1].ToLower() }

function Resolve-Account {
    param([string]$Sid)
    try { return (New-Object System.Security.Principal.SecurityIdentifier($Sid)).Translate([System.Security.Principal.NTAccount]).Value }
    catch { return '<unresolved>' }
}

function Backup-ProfileKey {
    param([string]$KeyName)
    if (-not (Test-Path -LiteralPath $backupDir)) { New-Item -ItemType Directory -Path $backupDir -Force | Out-Null }
    $file = Join-Path $backupDir (($KeyName -replace '[^A-Za-z0-9.\-]', '_') + '.reg')
    & reg.exe export "$profileListReg\$KeyName" $file /y 2>&1 | Out-Null
    if ($LASTEXITCODE -eq 0) { return $file }
    return $null
}

function Remove-ProfileFolder {
    # Moves to quarantine or deletes; takes ownership if ACLs block deletion.
    param([string]$Path)
    if ($QuarantinePath) {
        if (-not (Test-Path -LiteralPath $QuarantinePath)) { New-Item -ItemType Directory -Path $QuarantinePath -Force | Out-Null }
        $dest = Join-Path $QuarantinePath ('{0}_{1}' -f (Split-Path $Path -Leaf), $stamp)
        Move-Item -LiteralPath $Path -Destination $dest -ErrorAction SilentlyContinue
        return -not (Test-Path -LiteralPath $Path)
    }
    Remove-Item -LiteralPath $Path -Recurse -Force -ErrorAction SilentlyContinue
    if (Test-Path -LiteralPath $Path) {
        & takeown.exe /F $Path /R /A /D Y 2>&1 | Out-Null
        & icacls.exe $Path /grant '*S-1-5-32-544:(OI)(CI)F' /T /C /Q 2>&1 | Out-Null
        Remove-Item -LiteralPath $Path -Recurse -Force -ErrorAction SilentlyContinue
    }
    return -not (Test-Path -LiteralPath $Path)
}

function Get-FolderAudit {
    param([string]$Path)
    $all = @(Get-ChildItem -LiteralPath $Path -Recurse -File -Force -ErrorAction SilentlyContinue)
    $userFiles = @(foreach ($sub in 'Desktop', 'Documents', 'Downloads', 'Favorites', 'Pictures', 'Videos', 'Music') {
            $p = Join-Path $Path $sub
            if (Test-Path -LiteralPath $p) {
                Get-ChildItem -LiteralPath $p -Recurse -File -Force -ErrorAction SilentlyContinue | Where-Object { $_.Name -ne 'desktop.ini' -and $_.Extension -ne '.lnk' }
            }
        })
    [PSCustomObject]@{
        SizeMB    = [Math]::Round(($all | Measure-Object Length -Sum).Sum / 1MB, 1)
        Files     = $all.Count
        UserFiles = $userFiles.Count
        UserMB    = [Math]::Round(($userFiles | Measure-Object Length -Sum).Sum / 1MB, 1)
        Newest    = if ($all) { ($all | Sort-Object LastWriteTime -Descending | Select-Object -First 1).LastWriteTime.ToString('yyyy-MM-dd') } else { '' }
    }
}

Write-Host "Server $env:COMPUTERNAME, mode $(if ($Execute) { 'EXECUTE' } else { 'DRY RUN' })" -ForegroundColor $(if ($Execute) { 'Yellow' } else { 'Green' })

$loadedHives = @(Get-ChildItem Registry::HKEY_USERS | Where-Object { $_.PSChildName -notlike '*_Classes' } | ForEach-Object PSChildName)
$sessionUsers = @(& query.exe user 2>&1 | ForEach-Object { "$_" } | Select-Object -Skip 1 | ForEach-Object { (($_ -replace '^\s*>', '').Trim() -split '\s+')[0].ToLower() } | Where-Object { $_ })
$excluded = @($ExcludeUser | ForEach-Object { Get-Short $_ })

$entries = @(foreach ($k in (Get-ChildItem $profileListPs)) {
        $props = Get-ItemProperty -Path $k.PSPath
        $path = if ($props.PSObject.Properties['ProfileImagePath']) { $props.ProfileImagePath } else { $null }
        $sid = $k.PSChildName -replace '\.bak$', ''
        $account = Resolve-Account $sid
        [PSCustomObject]@{
            KeyName = $k.PSChildName; Sid = $sid; IsBak = $k.PSChildName -like '*.bak'; Account = $account; Short = Get-Short $account
            Path = $path; PathExists = [bool]($path -and (Test-Path -LiteralPath $path))
            HiveLoaded = $loadedHives -contains $sid; InSession = $sessionUsers -contains (Get-Short $account)
        }
    })

if (-not $FixRegistry -and -not $CleanFolders -and -not $RestoreUser) {
    $FixRegistry = $true; $CleanFolders = $true
    Write-Host 'No action given: planning -FixRegistry and -CleanFolders.' -ForegroundColor DarkGray
}

$planRegistry = @()
if ($FixRegistry) {
    $planRegistry = @(foreach ($e in ($entries | Where-Object { $_.Sid -like 'S-1-5-21-*' -and -not $_.PathExists })) {
            $reason = if ($e.HiveLoaded) { 'hive loaded' } elseif ($e.InSession) { 'session' } elseif ($excluded -contains $e.Short) { 'excluded' } else { '' }
            [PSCustomObject]@{ Account = $e.Account; KeyName = $e.KeyName; Path = $e.Path; Action = if ($reason) { "skip ($reason)" } else { 'remove entry' } }
        })
    Write-Host "`n1. Dangling ProfileList entries (folder does not exist)" -ForegroundColor Cyan
    if ($planRegistry) { $planRegistry | Format-Table -AutoSize | Out-Host } else { Write-Host '   none' }
}

$planFolders = @()
if ($CleanFolders) {
    $known = @($entries | Where-Object Path | ForEach-Object { $_.Path.TrimEnd('\').ToLower() })
    $cutoff = (Get-Date).AddMonths(-$FolderAgeMonths)
    $leftoverPattern = '\.BACKUP-\d+$|\.\d{3}$|^TEMP(\.|$)|\.' + [regex]::Escape($Domain) + '$'
    $planFolders = @(foreach ($d in (Get-ChildItem -LiteralPath $usersRoot -Directory -Force)) {
            if ($protectedFolders -contains $d.Name -or $known -contains $d.FullName.ToLower()) { continue }
            $isLeftover = $d.Name -match $leftoverPattern
            if (-not $isLeftover -and -not $IncludePlainOrphans) { continue }
            $owner = (($d.Name -split '\.')[0] -replace '^old_', '').ToLower()
            $reason = if ($excluded -contains $owner) { 'excluded' } elseif (-not $isLeftover -and $sessionUsers -contains $owner) { 'owner logged on' } elseif ($FolderAgeMonths -and $d.LastWriteTime -gt $cutoff) { "newer than $FolderAgeMonths months" } else { '' }
            $row = [ordered]@{ Folder = $d.Name; Path = $d.FullName; Modified = $d.LastWriteTime.ToString('yyyy-MM-dd'); Kind = if ($isLeftover) { 'leftover' } else { 'orphan' }; Action = if ($reason) { "skip ($reason)" } else { if ($QuarantinePath) { 'quarantine' } else { 'delete' } } }
            if ($Audit) { $a = Get-FolderAudit $d.FullName; foreach ($p in $a.PSObject.Properties) { $row[$p.Name] = $p.Value } }
            [PSCustomObject]$row
        })
    Write-Host "`n2. Orphan profile folders (no ProfileList entry)" -ForegroundColor Cyan
    if ($planFolders) { $planFolders | Sort-Object Action, Folder | Format-Table -AutoSize -Property * -Wrap | Out-String -Width 220 | Out-Host } else { Write-Host '   none' }
    if ($Audit -and $planFolders) { Write-Host '   UserFiles/UserMB: files in Desktop, Documents, Downloads, Favorites, Pictures, Videos, Music (no shortcuts). Zero means no user data.' -ForegroundColor DarkGray }
}

if ($RestoreUser) {
    Write-Host "`n3. Restore profile of $RestoreUser" -ForegroundColor Cyan
    $short = Get-Short $RestoreUser
    $target = Join-Path $usersRoot $short
    $source = if ($FromFolder) { Join-Path $usersRoot $FromFolder } else { '' }
    $mine = @($entries | Where-Object Short -eq $short)
    $main = $mine | Where-Object { -not $_.IsBak } | Select-Object -First 1
    $bak = $mine | Where-Object IsBak | Select-Object -First 1

    $problems = @()
    if (-not $mine) { $problems += "no ProfileList entries for $short" }
    if ($mine | Where-Object { $_.HiveLoaded -or $_.InSession }) { $problems += 'the user is logged on: log the session off first' }
    if (-not $FromFolder) { $problems += 'use -FromFolder to name the folder to restore from' }
    elseif (-not (Test-Path -LiteralPath $source)) { $problems += "source folder not found: $source" }
    if (Test-Path -LiteralPath $target) { $problems += "target folder already exists: $target" }

    Write-Host "   source: $source`n   target: $target"
    Write-Host ('   entry : {0}' -f $(if ($main) { "$($main.KeyName) -> $($main.Path)" } else { 'none' }))
    Write-Host ('   .bak  : {0}' -f $(if ($bak) { "$($bak.KeyName) -> $($bak.Path)" } else { 'none' }))
    if ($problems) { $problems | ForEach-Object { Write-Host "   CANNOT RESTORE: $_" -ForegroundColor Red } }
    elseif ($Execute) {
        try {
            foreach ($e in @($main, $bak) | Where-Object { $_ }) { if (-not (Backup-ProfileKey $e.KeyName)) { throw "cannot back up $($e.KeyName)" } }
            Rename-Item -LiteralPath $source -NewName $short
            $tempPath = $null
            if ($main) { $tempPath = $main.Path; Remove-Item -LiteralPath "$profileListPs\$($main.KeyName)" -Recurse -Force }
            $finalKey = "$profileListPs\$((@($bak, $main) | Where-Object { $_ } | Select-Object -First 1).Sid)"
            if ($bak) {
                & reg.exe copy "$profileListReg\$($bak.KeyName)" "$profileListReg\$($bak.Sid)" /s /f 2>&1 | Out-Null
                if ($LASTEXITCODE -ne 0) { throw 'reg copy failed' }
                & reg.exe delete "$profileListReg\$($bak.KeyName)" /f 2>&1 | Out-Null
            }
            Set-ItemProperty -Path $finalKey -Name ProfileImagePath -Value $target
            Set-ItemProperty -Path $finalKey -Name State -Value 0 -Type DWord
            Set-ItemProperty -Path $finalKey -Name RefCount -Value 0 -Type DWord
            if ($RemoveTempFolder -and $tempPath -and $tempPath -match '\\TEMP' -and (Test-Path -LiteralPath $tempPath)) { [void](Remove-ProfileFolder $tempPath) }
            Write-Host "   Restored. Ask $short to log on and check the profile." -ForegroundColor Green
        }
        catch {
            Write-Host "   ERROR: $($_.Exception.Message). Registry backups: $backupDir (import the .reg files to roll back)" -ForegroundColor Red
        }
    }
}

if ($Execute) {
    foreach ($r in ($planRegistry | Where-Object Action -eq 'remove entry')) {
        if (-not (Backup-ProfileKey $r.KeyName)) { Write-Host "   skip $($r.Account): backup failed" -ForegroundColor Yellow; continue }
        Remove-Item -LiteralPath "$profileListPs\$($r.KeyName)" -Recurse -Force
        Write-Host "   removed entry $($r.Account) [$($r.KeyName)]" -ForegroundColor Green
    }
    foreach ($f in ($planFolders | Where-Object { $_.Action -in 'delete', 'quarantine' })) {
        if (Remove-ProfileFolder $f.Path) { Write-Host "   $($f.Action): $($f.Folder)" -ForegroundColor Green }
        else { Write-Host "   FAILED: $($f.Folder)" -ForegroundColor Red }
    }
    if (Test-Path -LiteralPath $backupDir) { Write-Host "Registry backups: $backupDir (roll back with reg.exe import <file>)" -ForegroundColor DarkGray }
}
else {
    Write-Host "`nDry run: nothing changed. Add -Execute to apply." -ForegroundColor Yellow
}
Stop-Transcript | Out-Null

@($planRegistry) + @($planFolders)
