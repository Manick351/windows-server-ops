# windows-server-ops

PowerShell tools for running a Windows Server fleet: parallel patching with reboot control, Active Directory
and LAPS checks, account lockout tracing, mass logoff, disk and profile cleanup, free IP search,
access and vulnerability audits, network printers.

> **🇷🇺 Кратко.** PowerShell-инструменты для обслуживания парка Windows-серверов: параллельный патчинг с
> ограничением одновременных перезагрузок и проверкой служб, аудит LAPS, поиск источника блокировок учёток,
> разлогин учётки на всех серверах, очистка дисков и профилей, поиск свободных IP, аудит прав на папки и Tomcat,
> сетевые принтеры. Всё, что меняет систему, по умолчанию работает как сухой прогон (`-Execute`) или
> поддерживает `-WhatIf`.

## Contents

| Area | Script | What it does | Changes anything? |
|---|---|---|---|
| Patching | [patching/Invoke-ServerPatching.ps1](patching/Invoke-ServerPatching.ps1) | Patches many servers in parallel: PSWindowsUpdate via a SYSTEM task, reboot semaphore, wait for boot, service check, held services, control files | Dry run unless `-Execute` |
| | [patching/Get-PatchingStatus.ps1](patching/Get-PatchingStatus.ps1) | Live status table of a patching run | No |
| | [patching/Set-PatchingControl.ps1](patching/Set-PatchingControl.ps1) | Stop a server's job or approve its reboot | `-WhatIf` |
| | [patching/New-ZabbixMaintenance.ps1](patching/New-ZabbixMaintenance.ps1) | Zabbix maintenance window for a list of hosts (API token or login) | `-WhatIf` |
| Active Directory | [ad/Get-LapsStatus.ps1](ad/Get-LapsStatus.ps1) | LAPS password present / expired / missing per computer, reachability of problem ones, HTML e-mail report | No |
| | [ad/Compare-LapsConfiguration.ps1](ad/Compare-LapsConfiguration.ps1) | Side-by-side LAPS facts of a working and a broken computer | No |
| | [ad/Watch-AccountLockout.ps1](ad/Watch-AccountLockout.ps1) | Polls every DC for badPwdCount / lockoutTime of an account, optional 4740 lookup | No |
| | [ad/Resolve-LockoutSource.ps1](ad/Resolve-LockoutSource.ps1) | Turns client IPs from security events into hosts (PTR, AD forward lookup, port hints) | No |
| | [ad/Compare-ADGroupMembership.ps1](ad/Compare-ADGroupMembership.ps1) | Common, candidate and exclusive groups of several users, attribute comparison | No |
| Sessions | [sessions/Invoke-AccountLogoff.ps1](sessions/Invoke-AccountLogoff.ps1) | Logs an account off every server, detects stale DNS, classifies unreachable servers | `-WhatIf` / `-Confirm` |
| Maintenance | [maintenance/Clear-ServerDisk.ps1](maintenance/Clear-ServerDisk.ps1) | Remote cleanup of caches, temp, dumps, logs, WU cache and component store, with diagnostics | Dry run unless `-Execute` |
| | [maintenance/Remove-OldFiles.ps1](maintenance/Remove-OldFiles.ps1) | Retention cleanup of exchange/archive folders from a `.psd1`, root and depth guards | Dry run unless `-Execute` |
| | [maintenance/Register-ScriptTask.ps1](maintenance/Register-ScriptTask.ps1) | Registers a script as a scheduled task (interval/daily/weekly/monthly) under a gMSA, SYSTEM or account | `-WhatIf` |
| | [maintenance/Backup-DeviceDrivers.ps1](maintenance/Backup-DeviceDrivers.ps1) | Exports all third-party drivers | `-WhatIf` |
| Profiles | [profiles/Repair-LocalProfile.ps1](profiles/Repair-LocalProfile.ps1) | Dangling ProfileList entries, orphan profile folders (with data audit), profile restore from a backup folder | Dry run unless `-Execute` |
| Network | [network/Find-FreeIPAddress.ps1](network/Find-FreeIPAddress.ps1) | Free IPs in a /24: ping + TTL, PTR, ARP, inventory; network/broadcast/gateway checks | No |
| Files | [files/Get-FolderAccess.ps1](files/Get-FolderAccess.ps1) | NTFS access in plain terms, explicit entries in a tree | No |
| Security | [security/Get-TomcatAudit.ps1](security/Get-TomcatAudit.ps1) | Tomcat inventory and exposure to CVE-2020-1938, CVE-2023-44487, CVE-2025-24813 | No |
| | [security/Set-7ZipZoneId.ps1](security/Set-7ZipZoneId.ps1) | 7-Zip Mark-of-the-Web propagation for every user (loaded/offline hives, Default, Active Setup) | Dry run unless `-Execute` |
| Printers | [printers/Find-NetworkPrinter.ps1](printers/Find-NetworkPrinter.ps1) | Finds printers by TCP 9100, reads model, serial, page count and toner over SNMP | No |
| | [printers/Remove-RemotePrinter.ps1](printers/Remove-RemotePrinter.ps1) | Removes selected printers from a remote computer | `-WhatIf` / `-Confirm` |
| | [printers/Invoke-PrinterTestPage.ps1](printers/Invoke-PrinterTestPage.ps1) | Prints a test page on printers of a remote computer | `-WhatIf` |
| | [printers/Restart-NetworkPrinter.ps1](printers/Restart-NetworkPrinter.ps1) | Power-cycles printers via SNMP `prtGeneralReset` | `-WhatIf` / `-Confirm` |

## Requirements

- Windows PowerShell 5.1 (PowerShell 7 works for most scripts), WinRM to the managed servers.
- `ActiveDirectory` module only for `Get-LapsStatus`, `Compare-ADGroupMembership` and server selection in
  `Set-7ZipZoneId`; other AD scripts use LDAP directly.
- `PSWindowsUpdate` on target servers for patching (or `-PSWindowsUpdateSource` to copy it).
- Printer scripts use the built-in `olePrn.OleSNMP` COM object and the `PrintManagement` module.

Every script has comment-based help: `Get-Help .\patching\Invoke-ServerPatching.ps1 -Full`.

## Patching

```powershell
# 1. dry run: who needs a reboot, how many updates are available
.\patching\Invoke-ServerPatching.ps1 -ScheduleCsv .\schedule.csv -Window 18:00-23:59

# 2. real run: domain account first, local admin as a fallback, at most 5 servers rebooting at once
$creds = (Get-Credential CONTOSO\adm-patch), (Import-Clixml C:\Secure\local-admin.xml)
.\patching\Invoke-ServerPatching.ps1 -ScheduleCsv .\schedule.csv -Window 18:00-23:59 -Credential $creds `
    -Execute -MaxParallelReboots 5 -HoldServicePattern '^Contoso\.(Print|Label)'

# 3. in another window: watch, approve or stop single servers
.\patching\Get-PatchingStatus.ps1 -WorkFolder .\PatchRun_20261008_1800 -Watch
.\patching\Set-PatchingControl.ps1 -WorkFolder .\PatchRun_20261008_1800 -ComputerName srv-db-01.contoso.local -Action Reboot
```

```text
Patching status 19:42:10  .\PatchRun_20261008_1800
Finished 3 of 5: Finished=2, Skipped=1
srv-app-01.contoso.local  Finished                               Finished           reboots 1 inst   4 fail  0 free   18.4 00:47
srv-app-02.contoso.local  Installing: KB5066000 2026-10 Cumulat                     reboots 0 inst   0 fail  0 free   11.9 00:51
srv-db-01.contoso.local   Waiting for reboot approval                               reboots 0 inst   3 fail  0 free   42.0 00:38
srv-file-01.contoso.local Finished                               Finished           reboots 2 inst   6 fail  0 free   27.3 01:05
dc-01.contoso.local       Skipped                                Skipped            reboots 0 inst   0 fail  0 free   31.0 00:00
```

How it works:

- **Why a scheduled task.** The Windows Update API refuses to download and install from a remote (network logon)
  session. Each round registers a one-time task running as SYSTEM, which runs PSWindowsUpdate and writes a progress
  log; the worker polls that log over WinRM and removes the task afterwards.
- **Reboot concurrency.** All workers share one `SemaphoreSlim`; a worker takes a slot before `Restart-Computer`
  and releases it once `LastBootUpTime` has changed (or on timeout), so no more than `-MaxParallelReboots`
  servers are down at once.
- **Service check.** Automatic services running before the first reboot are compared with the state after the
  last one; stopped ones are started and reported if they stay down.
- **Files as the interface.** `status\<server>.json` (atomic replace), `logs\<server>.tsv` (event log for later
  analysis) and `control\<server>.txt` (Stop / Reboot) make the run observable and steerable from any shell.

## Examples

```powershell
# where is the admin account still logged on? (report only)
.\sessions\Invoke-AccountLogoff.ps1 -UserName adm-jdoe -WhatIf

# monthly LAPS report by e-mail (run as a scheduled task)
.\ad\Get-LapsStatus.ps1 -SearchBase 'OU=Servers,DC=contoso,DC=local' -SmtpServer smtp.contoso.local -UseSsl `
    -From laps@contoso.local -To it-ops@contoso.local -MailCredential (Import-Clixml C:\Secure\smtp.xml)

# which DC sees the bad passwords, then who is behind the client IP
.\ad\Watch-AccountLockout.ps1 -UserName svc-backup -QueryPdcEvents
.\ad\Resolve-LockoutSource.ps1 -IPAddress 10.0.0.42 -ScanPorts

# free address for a new server, excluding everything known to the CMDB
.\network\Find-FreeIPAddress.ps1 -Subnet 10.0.0 -Range 100-199 -KnownAddress (Import-Csv .\cmdb.csv).IPAddress -OnlyFree

# what can be freed on a group of servers
Get-Content .\servers.txt | .\maintenance\Clear-ServerDisk.ps1

# printers running out of toner
.\printers\Find-NetworkPrinter.ps1 -Subnet 192.0.2 | Where-Object TonerPercent -lt 15
```

`Find-FreeIPAddress.ps1` output (illustrative):

```text
IPAddress   Status    Name        TTL OSHint     Detail
---------   ------    ----        --- ------     ------
10.0.0.160  NETWORK                              network address of 10.0.0.160/29 (given)
10.0.0.161  GATEWAY   gw-dmz-01   255 network    gateway of 10.0.0.160/29, answers, TTL 255
10.0.0.162  BUSY      srv-web-01  128 Windows    ping 1 ms; PTR srv-web-01.contoso.local
10.0.0.163  CHECK     srv-old-03                 PTR srv-old-03.contoso.local; no answer but a DNS/inventory trace remains
10.0.0.164  FREE
10.0.0.167  BROADCAST                            broadcast of 10.0.0.160/29 (given)
```

Configuration examples: [examples/patch-schedule.example.csv](examples/patch-schedule.example.csv),
[examples/cleanup-targets.example.psd1](examples/cleanup-targets.example.psd1).

## Safety conventions

- Batch scripts that delete or reboot are **dry runs unless `-Execute`** is given; interactive single actions use
  `-WhatIf` / `-Confirm`.
- Registry changes are preceded by a `.reg` export; profile folders can go to a quarantine folder instead of being deleted.
- Passwords are never passed on the command line: `Get-Credential`, `Import-Clixml` (DPAPI) or SecretManagement.
- Read-only tools never read secrets: LAPS checks look at presence and expiry only, Tomcat audit masks `password=` values.

## Limitations

- Patching relies on PSWindowsUpdate and Microsoft Update / WSUS as configured on the servers; it does not approve updates.
- Free IP search covers one /24 per run; TTL hints are heuristics.
- Printer scripts: IPv4 /24 ranges, SNMP v1/v2c, first marker supply only.

## History

This repository was previously named `PowerShell` and contained printer scripts; they now live in `printers/`
(`Net_Print_finder_ver2` and three earlier scanners became `Find-NetworkPrinter.ps1`).

## License

[MIT](LICENSE)
