<#
.SYNOPSIS
    Makes 7-Zip propagate Mark-of-the-Web (Zone.Identifier) to extracted files for every user on remote servers.
    Dry run by default.

.DESCRIPTION
    By default 7-Zip does not copy the Zone.Identifier stream from a downloaded archive to the files it
    extracts, so a document or script from the internet loses its "downloaded" mark and opens without
    Protected View / SmartScreen. 7-Zip 22.00+ has a per-user option HKCU\Software\7-Zip\Options\WriteZoneIdExtract:
      0 = do not write, 1 = write for all files, 2 = write for Office files only.

    The option is per user, so on a multi-user server the script sets it:
      - in every loaded user hive (HKU\<SID>);
      - in every unloaded profile (NTUSER.DAT is loaded under a temporary name, changed, unloaded,
        with retries and garbage collection so the hive is not left locked);
      - in the Default profile (new users);
      - through an Active Setup component, so profiles that could not be reached (UPD, FSLogix, roaming)
        get the value at their next logon.

    The 7-Zip version is checked and reported. Without -Execute only the plan is shown.

.PARAMETER ComputerName
    Servers. If omitted, a grid with enabled Windows servers from AD is shown for selection
    (ActiveDirectory module), or names are asked for.

.PARAMETER Value
    0, 1 or 2. Default: 1.

.PARAMETER Execute
    Apply the change. Without it the script is a dry run.

.PARAMETER NoActiveSetup
    Do not register the Active Setup component.

.PARAMETER Credential
    Optional credential for WinRM.

.EXAMPLE
    .\Set-7ZipZoneId.ps1 -ComputerName rds-sh-01, rds-sh-02

.EXAMPLE
    .\Set-7ZipZoneId.ps1 -ComputerName rds-sh-01 -Value 2 -Execute
#>
#Requires -Version 5.1
[CmdletBinding()]
param(
    [string[]]$ComputerName,
    [ValidateSet(0, 1, 2)][int]$Value = 1,
    [switch]$Execute,
    [switch]$NoActiveSetup,
    [pscredential]$Credential,
    [string]$LogPath = (Join-Path $env:ProgramData 'windows-server-ops\logs')
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if (-not (Test-Path -LiteralPath $LogPath)) { New-Item -ItemType Directory -Path $LogPath -Force | Out-Null }
$logFile = Join-Path $LogPath ('Set-7ZipZoneId_{0:yyyyMMdd_HHmmss}.log' -f (Get-Date))

function Write-Log {
    param([string]$Message, [string]$Level = 'INFO')
    $line = '{0:yyyy-MM-dd HH:mm:ss} [{1}] {2}' -f (Get-Date), $Level, $Message
    Write-Host $line -ForegroundColor $(switch ($Level) { 'ERROR' { 'Red' } 'WARN' { 'Yellow' } 'OK' { 'Green' } 'PLAN' { 'Cyan' } default { 'Gray' } })
    [IO.File]::AppendAllText($logFile, $line + "`r`n", [Text.Encoding]::UTF8)
}

$remote = {
    param([int]$Value, [bool]$Apply, [bool]$UseActiveSetup)
    $ErrorActionPreference = 'Stop'
    $subKey = 'Software\7-Zip\Options'
    $valueName = 'WriteZoneIdExtract'
    $activeSetupId = '{7A1F2C3D-5B6E-4F70-9A1B-2C3D4E5F6071}'
    $res = New-Object System.Collections.Generic.List[object]
    function Add-Result([string]$Target, [string]$Status, [string]$Detail) { $res.Add([PSCustomObject]@{ Target = $Target; Status = $Status; Detail = $Detail }) }
    function Get-ErrorText($Record) {
        $e = $Record.Exception
        while ($e.InnerException) { $e = $e.InnerException }
        [PSCustomObject]@{ Denied = ($e -is [UnauthorizedAccessException] -or $e -is [Security.SecurityException]); Text = ($e.Message -replace '\s+', ' ').Trim() }
    }

    function Set-HiveValue([string]$HivePath) {
        $k = [Microsoft.Win32.Registry]::Users.OpenSubKey("$HivePath\$subKey", $false)
        $current = $null
        if ($k) { $current = $k.GetValue($valueName, $null); $k.Close() }
        $currentText = if ($null -eq $current) { 'absent' } else { "$current" }
        if ($null -ne $current -and [int]$current -eq $Value) { return 'SKIP', "already $current" }
        if (-not $Apply) { return 'PLAN', "$currentText -> $Value" }
        $k = [Microsoft.Win32.Registry]::Users.CreateSubKey("$HivePath\$subKey")
        try { $k.SetValue($valueName, $Value, [Microsoft.Win32.RegistryValueKind]::DWord) } finally { $k.Close() }
        return 'OK', "$currentText -> $Value"
    }

    function Set-OfflineHive([string]$DatPath) {
        $mount = 'Z7_' + [guid]::NewGuid().ToString('N').Substring(0, 8)
        $out = & reg.exe load "HKU\$mount" $DatPath 2>&1
        if ($LASTEXITCODE -ne 0) { throw "reg load failed: $out" }
        $r = $null; $err = $null
        try { $r = Set-HiveValue $mount } catch { $err = $_ }
        [GC]::Collect(); [GC]::WaitForPendingFinalizers()
        $unloaded = $false
        for ($i = 0; $i -lt 5 -and -not $unloaded; $i++) {
            & reg.exe unload "HKU\$mount" 2>&1 | Out-Null
            if ($LASTEXITCODE -eq 0) { $unloaded = $true } else { Start-Sleep -Seconds 1 }
        }
        if (-not $unloaded) { throw "value handled, but the hive could not be unloaded from HKU\$mount" }
        if ($err) { throw $err }
        return $r
    }

    $exe = @("$env:ProgramFiles\7-Zip\7z.exe", "${env:ProgramFiles(x86)}\7-Zip\7z.exe") | Where-Object { $_ -and (Test-Path -LiteralPath $_) } | Select-Object -First 1
    if ($exe) {
        $vi = (Get-Item -LiteralPath $exe).VersionInfo
        if ($vi.FileMajorPart -lt 22) { Add-Result '7-Zip' 'WARN' "$exe $($vi.ProductVersion): the option needs 22.00 or newer" }
        else { Add-Result '7-Zip' 'INFO' "$exe $($vi.ProductVersion)" }
    }
    else { Add-Result '7-Zip' 'WARN' '7z.exe not found; the setting is written anyway' }

    $profileList = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList'
    $loaded = [Microsoft.Win32.Registry]::Users.GetSubKeyNames()
    foreach ($p in (Get-ChildItem -LiteralPath $profileList | Where-Object { $_.PSChildName -match '^S-1-5-21-[\d-]+$' })) {
        $sid = $p.PSChildName
        $path = $p.GetValue('ProfileImagePath')
        $user = $sid
        try { $user = (New-Object Security.Principal.SecurityIdentifier($sid)).Translate([Security.Principal.NTAccount]).Value } catch { }
        $target = "$user ($path)"
        try {
            if ($loaded -contains $sid) { $st, $dt = Set-HiveValue $sid; Add-Result $target $st "loaded hive: $dt"; continue }
            $dat = Join-Path $path 'NTUSER.DAT'
            if (-not (Test-Path -LiteralPath $dat)) { Add-Result $target 'SKIP' 'NTUSER.DAT not found (UPD/FSLogix/roaming): covered by Active Setup'; continue }
            if (-not $Apply) { Add-Result $target 'PLAN' "offline hive will be loaded and set to $Value"; continue }
            $st, $dt = Set-OfflineHive $dat
            Add-Result $target $st "offline hive: $dt"
        }
        catch {
            $e = Get-ErrorText $_
            if ($e.Denied) { Add-Result $target 'WARN' "no access to the hive, covered by Active Setup at next logon: $($e.Text)" }
            else { Add-Result $target 'ERROR' $e.Text }
        }
    }

    try {
        $defaultDat = Join-Path (Get-ItemProperty -LiteralPath $profileList).Default 'NTUSER.DAT'
        if (-not (Test-Path -LiteralPath $defaultDat)) { Add-Result 'Default profile' 'WARN' "$defaultDat not found" }
        elseif (-not $Apply) { Add-Result 'Default profile' 'PLAN' "$defaultDat will be loaded and set to $Value" }
        else { $st, $dt = Set-OfflineHive $defaultDat; Add-Result 'Default profile' $st $dt }
    }
    catch { Add-Result 'Default profile' 'ERROR' (Get-ErrorText $_).Text }

    if ($UseActiveSetup) {
        try {
            $asPath = "HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\$activeSetupId"
            $stub = "reg.exe add HKCU\Software\7-Zip\Options /v $valueName /t REG_DWORD /d $Value /f"
            $current = Get-ItemProperty -LiteralPath $asPath -ErrorAction SilentlyContinue
            if ($current -and $current.StubPath -eq $stub -and $current.IsInstalled -eq 1) { Add-Result 'Active Setup' 'SKIP' 'already configured' }
            elseif (-not $Apply) { Add-Result 'Active Setup' 'PLAN' "StubPath: $stub" }
            else {
                # A new Version makes Active Setup run again for users who already ran an older version.
                $version = Get-Date -Format 'yyyy,MMdd,HHmm,0'
                New-Item -Path $asPath -Force | Out-Null
                Set-ItemProperty -LiteralPath $asPath -Name '(default)' -Value '7-Zip WriteZoneIdExtract'
                Set-ItemProperty -LiteralPath $asPath -Name StubPath -Value $stub
                Set-ItemProperty -LiteralPath $asPath -Name Version -Value $version
                New-ItemProperty -LiteralPath $asPath -Name IsInstalled -Value 1 -PropertyType DWord -Force | Out-Null
                Add-Result 'Active Setup' 'OK' "version $version"
            }
        }
        catch { Add-Result 'Active Setup' 'ERROR' (Get-ErrorText $_).Text }
    }
    $res
}

if (-not $ComputerName) {
    if (Get-Module -ListAvailable -Name ActiveDirectory) {
        $ComputerName = Get-ADComputer -Filter 'OperatingSystem -like "*Server*" -and Enabled -eq $true' -Properties OperatingSystem, Description |
            Sort-Object Name | Select-Object Name, OperatingSystem, Description |
            Out-GridView -Title 'Select servers (Ctrl/Shift for several)' -PassThru | ForEach-Object Name
    }
    else { $ComputerName = (Read-Host 'Server names, separated by comma or space') -split '[,;\s]+' }
}
$ComputerName = @($ComputerName | Where-Object { $_ } | ForEach-Object { $_.Trim().ToUpper() } | Sort-Object -Unique)
if (-not $ComputerName) { Write-Warning 'No servers selected.'; return }

Write-Log ("mode {0} | value {1} | Active Setup {2} | {3}\{4} on {5}" -f $(if ($Execute) { 'EXECUTE' } else { 'DRY RUN' }), $Value, (-not $NoActiveSetup), $env:USERDOMAIN, $env:USERNAME, $env:COMPUTERNAME)
Write-Log "Servers ($($ComputerName.Count)): $($ComputerName -join ', ')"

$params = @{ ComputerName = $ComputerName; ScriptBlock = $remote; ArgumentList = $Value, [bool]$Execute, (-not $NoActiveSetup); ErrorAction = 'SilentlyContinue'; ErrorVariable = 'remoteErrors' }
if ($Credential) { $params.Credential = $Credential }
$results = @(Invoke-Command @params)

foreach ($group in ($results | Group-Object PSComputerName | Sort-Object Name)) {
    Write-Log "===== $($group.Name)"
    foreach ($r in $group.Group) {
        $level = if ($r.Status -in 'OK', 'PLAN', 'ERROR', 'WARN') { $r.Status } else { 'INFO' }
        Write-Log ('{0,-5} {1} | {2}' -f $r.Status, $r.Target, $r.Detail) $level
    }
}
foreach ($e in $remoteErrors) {
    $name = if ($e.OriginInfo -and $e.OriginInfo.PSComputerName) { $e.OriginInfo.PSComputerName } elseif ($e.TargetObject) { "$($e.TargetObject)" } else { 'unknown' }
    Write-Log "===== $name : $($e.Exception.Message)" 'ERROR'
}
$stats = $results | Group-Object Status | ForEach-Object { "$($_.Name)=$($_.Count)" }
Write-Log "Summary: $(@($results | ForEach-Object PSComputerName | Sort-Object -Unique).Count) server(s) processed, $(@($remoteErrors).Count) failed | $($stats -join ', ')"
if (-not $Execute) { Write-Log 'DRY RUN: nothing changed. Add -Execute to apply.' 'PLAN' }
Write-Log "Log: $logFile"
$results | Select-Object PSComputerName, Target, Status, Detail
