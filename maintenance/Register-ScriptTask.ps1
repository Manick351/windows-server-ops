<#
.SYNOPSIS
    Registers a PowerShell script as a scheduled task: interval, daily, weekly or monthly, under a service
    account, a gMSA or SYSTEM.

.DESCRIPTION
    Wraps the ScheduledTasks module with sensible defaults for automation scripts:
      - action: powershell.exe or pwsh.exe -NoProfile -ExecutionPolicy Bypass -File <script> [arguments];
      - settings: no parallel instances, start when available, configurable execution time limit;
      - principal: a gMSA (no password at all), SYSTEM, or a service account whose password is asked
        for interactively with Get-Credential (never passed on the command line).

    The ScheduledTasks module cannot create monthly triggers, so for -Schedule Monthly the task is
    registered from XML with a CalendarTrigger / ScheduleByMonth element.

    Supports -WhatIf; -Force replaces an existing task with the same name.

.PARAMETER TaskName
    Task name; may include a folder, for example \Automation\Nightly-Report.

.PARAMETER ScriptPath
    Script to run.

.PARAMETER Arguments
    Extra arguments appended after the script path.

.PARAMETER Description
    Task description.

.PARAMETER Schedule
    Interval, Daily, Weekly or Monthly.

.PARAMETER At
    Start time (time of day; for Interval also the first run). Default: 03:00.

.PARAMETER Interval
    Repetition interval for -Schedule Interval, for example (New-TimeSpan -Minutes 15).

.PARAMETER DaysOfWeek
    Days for -Schedule Weekly.

.PARAMETER DayOfMonth
    Day (1-31) for -Schedule Monthly.

.PARAMETER RunAs
    gMSA name ending with $, SYSTEM, or a DOMAIN\user (password requested interactively).

.PARAMETER UsePwsh
    Run with PowerShell 7 (pwsh.exe) instead of Windows PowerShell 5.1.

.PARAMETER ExecutionTimeLimit
    Stop the task after this time. Default: 4 hours.

.PARAMETER WorkingDirectory
    Working directory. Default: the script folder.

.PARAMETER Force
    Replace an existing task.

.EXAMPLE
    .\Register-ScriptTask.ps1 -TaskName '\Automation\Cleanup' -ScriptPath D:\Scripts\Remove-OldFiles.ps1 `
        -Arguments '-ConfigPath D:\Scripts\cleanup.psd1 -Execute' -Schedule Daily -At 02:30 -RunAs 'CONTOSO\gmsa-automation$'

.EXAMPLE
    .\Register-ScriptTask.ps1 -TaskName 'LAPS monthly report' -ScriptPath D:\Scripts\Get-LapsStatus.ps1 -Schedule Monthly -DayOfMonth 1 -At 08:00 -RunAs 'CONTOSO\svc-reports'

.EXAMPLE
    .\Register-ScriptTask.ps1 -TaskName 'Queue watcher' -ScriptPath D:\Scripts\Watch-Queue.ps1 -Schedule Interval -Interval (New-TimeSpan -Minutes 5) -RunAs SYSTEM -WhatIf
#>
#Requires -Version 5.1
#Requires -RunAsAdministrator
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [Parameter(Mandatory = $true)][string]$TaskName,
    [Parameter(Mandatory = $true)][ValidateScript({ Test-Path -LiteralPath $_ -PathType Leaf })][string]$ScriptPath,
    [string]$Arguments = '',
    [string]$Description = '',

    [Parameter(Mandatory = $true)]
    [ValidateSet('Interval', 'Daily', 'Weekly', 'Monthly')]
    [string]$Schedule,

    [datetime]$At = (Get-Date).Date.AddHours(3),
    [timespan]$Interval,
    [DayOfWeek[]]$DaysOfWeek,
    [ValidateRange(1, 31)][int]$DayOfMonth,

    [Parameter(Mandatory = $true)][string]$RunAs,

    [switch]$UsePwsh,
    [timespan]$ExecutionTimeLimit = (New-TimeSpan -Hours 4),
    [string]$WorkingDirectory,
    [switch]$Force
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$ScriptPath = (Resolve-Path -LiteralPath $ScriptPath).Path
if (-not $WorkingDirectory) { $WorkingDirectory = Split-Path -Parent $ScriptPath }
$exe = if ($UsePwsh) { (Get-Command pwsh.exe -ErrorAction Stop).Source } else { "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" }
$argumentLine = ('-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "{0}" {1}' -f $ScriptPath, $Arguments).Trim()

$folder = '\'
$name = $TaskName
if ($TaskName -match '^(.*\\)([^\\]+)$') { $folder = $Matches[1]; $name = $Matches[2]; if (-not $folder.StartsWith('\')) { $folder = '\' + $folder } }

$startAt = (Get-Date).Date.Add($At.TimeOfDay)
if ($startAt -lt (Get-Date)) { $startAt = $startAt.AddDays(1) }

switch ($Schedule) {
    'Interval' {
        if (-not $Interval -or $Interval.TotalMinutes -lt 1) { throw 'Use -Interval of at least 1 minute with -Schedule Interval.' }
        $trigger = New-ScheduledTaskTrigger -Once -At $startAt -RepetitionInterval $Interval
    }
    'Daily' { $trigger = New-ScheduledTaskTrigger -Daily -At $startAt }
    'Weekly' {
        if (-not $DaysOfWeek) { throw 'Use -DaysOfWeek with -Schedule Weekly.' }
        $trigger = New-ScheduledTaskTrigger -Weekly -DaysOfWeek $DaysOfWeek -At $startAt
    }
    'Monthly' { if (-not $DayOfMonth) { throw 'Use -DayOfMonth with -Schedule Monthly.' } }
}

# Principal: gMSA ($ suffix) and SYSTEM need no password; a regular account is asked for one.
$credential = $null
if ($RunAs -match '\$$') {
    $principal = New-ScheduledTaskPrincipal -UserId $RunAs -LogonType Password -RunLevel Highest
    $logonType = 'Password'
}
elseif ($RunAs -in 'SYSTEM', 'NT AUTHORITY\SYSTEM') {
    $principal = New-ScheduledTaskPrincipal -UserId 'NT AUTHORITY\SYSTEM' -LogonType ServiceAccount -RunLevel Highest
    $logonType = 'ServiceAccount'
}
else {
    if (-not $WhatIfPreference) { $credential = Get-Credential -UserName $RunAs -Message "Password for the account that runs '$TaskName'" }
    $principal = New-ScheduledTaskPrincipal -UserId $RunAs -LogonType Password -RunLevel Highest
    $logonType = 'Password'
}

$action = New-ScheduledTaskAction -Execute $exe -Argument $argumentLine -WorkingDirectory $WorkingDirectory
$settings = New-ScheduledTaskSettingsSet -MultipleInstances IgnoreNew -StartWhenAvailable -AllowStartIfOnBatteries `
    -DontStopIfGoingOnBatteries -ExecutionTimeLimit $ExecutionTimeLimit

if (-not $PSCmdlet.ShouldProcess("$folder$name", "Register $Schedule task running $ScriptPath as $RunAs")) { return }

if (Get-ScheduledTask -TaskPath $folder -TaskName $name -ErrorAction SilentlyContinue) {
    if (-not $Force) { throw "Task $folder$name already exists. Use -Force to replace it." }
    Unregister-ScheduledTask -TaskPath $folder -TaskName $name -Confirm:$false
}

if ($Schedule -eq 'Monthly') {
    # Register with a placeholder trigger, export the XML, swap in a monthly CalendarTrigger, register again.
    $placeholder = New-ScheduledTaskTrigger -Once -At $startAt
    $task = New-ScheduledTask -Action $action -Trigger $placeholder -Settings $settings -Principal $principal -Description $Description
    $temp = @{ TaskPath = $folder; TaskName = $name; InputObject = $task }
    if ($credential) { $temp.User = $credential.UserName; $temp.Password = $credential.GetNetworkCredential().Password }
    Register-ScheduledTask @temp | Out-Null
    [xml]$xml = Export-ScheduledTask -TaskPath $folder -TaskName $name
    Unregister-ScheduledTask -TaskPath $folder -TaskName $name -Confirm:$false
    $ns = $xml.DocumentElement.NamespaceURI
    $triggers = $xml.Task.Triggers
    $triggers.RemoveAll()
    $calendar = $xml.CreateElement('CalendarTrigger', $ns)
    $start = $xml.CreateElement('StartBoundary', $ns); $start.InnerText = $startAt.ToString('s'); [void]$calendar.AppendChild($start)
    $enabled = $xml.CreateElement('Enabled', $ns); $enabled.InnerText = 'true'; [void]$calendar.AppendChild($enabled)
    $byMonth = $xml.CreateElement('ScheduleByMonth', $ns)
    $days = $xml.CreateElement('DaysOfMonth', $ns)
    $day = $xml.CreateElement('Day', $ns); $day.InnerText = "$DayOfMonth"; [void]$days.AppendChild($day)
    [void]$byMonth.AppendChild($days)
    $months = $xml.CreateElement('Months', $ns)
    foreach ($m in 'January', 'February', 'March', 'April', 'May', 'June', 'July', 'August', 'September', 'October', 'November', 'December') {
        [void]$months.AppendChild($xml.CreateElement($m, $ns))
    }
    [void]$byMonth.AppendChild($months)
    [void]$calendar.AppendChild($byMonth)
    [void]$triggers.AppendChild($calendar)

    $register = @{ TaskPath = $folder; TaskName = $name; Xml = $xml.OuterXml }
    if ($credential) { $register.User = $credential.UserName; $register.Password = $credential.GetNetworkCredential().Password }
    elseif ($logonType -eq 'ServiceAccount') { $register.User = 'NT AUTHORITY\SYSTEM' }
    Register-ScheduledTask @register | Out-Null
}
else {
    $task = New-ScheduledTask -Action $action -Trigger $trigger -Settings $settings -Principal $principal -Description $Description
    if ($credential) {
        Register-ScheduledTask -TaskPath $folder -TaskName $name -InputObject $task -User $credential.UserName -Password $credential.GetNetworkCredential().Password | Out-Null
    }
    else {
        Register-ScheduledTask -TaskPath $folder -TaskName $name -InputObject $task | Out-Null
    }
}

$registered = Get-ScheduledTask -TaskPath $folder -TaskName $name
Write-Host "Task $folder$name registered. Next run: $((Get-ScheduledTaskInfo -InputObject $registered).NextRunTime)" -ForegroundColor Green
Write-Host "Test it now: Start-ScheduledTask -TaskPath '$folder' -TaskName '$name'" -ForegroundColor DarkGray
$registered
