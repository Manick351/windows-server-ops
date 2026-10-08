# windows-server-ops

PowerShell tools for day-to-day Windows operations: network printers and workstation maintenance.

> **🇷🇺 Кратко.** PowerShell-скрипты для повседневного администрирования Windows: поиск сетевых принтеров
> в подсети с чтением модели, серийника, пробега и тонера по SNMP, удаление принтеров и тестовая печать на
> удалённых ПК, перезагрузка принтеров по SNMP, бэкап драйверов. Все скрипты с параметрами, справкой
> (`Get-Help`) и поддержкой `-WhatIf` там, где они что-то меняют.

## Contents

| Script | What it does | Changes anything? |
|---|---|---|
| [printers/Find-NetworkPrinter.ps1](printers/Find-NetworkPrinter.ps1) | Finds printers in a /24 by TCP 9100 and reads model, name, serial, page count and toner over SNMP | No (read-only) |
| [printers/Remove-RemotePrinter.ps1](printers/Remove-RemotePrinter.ps1) | Removes selected printers from a remote computer | Yes, `-WhatIf` / `-Confirm` |
| [printers/Invoke-PrinterTestPage.ps1](printers/Invoke-PrinterTestPage.ps1) | Prints a Windows test page on printers of a remote computer | Prints, `-WhatIf` |
| [printers/Restart-NetworkPrinter.ps1](printers/Restart-NetworkPrinter.ps1) | Power-cycles printers via SNMP `prtGeneralReset` | Yes, `-WhatIf` / `-Confirm` |
| [maintenance/Backup-DeviceDrivers.ps1](maintenance/Backup-DeviceDrivers.ps1) | Exports all third-party drivers (`Export-WindowsDriver`) | Writes to the destination folder, `-WhatIf` |

## Requirements

- Windows PowerShell 5.1 or PowerShell 7 on Windows.
- Printer scripts use the built-in `olePrn.OleSNMP` COM object (SNMP v1) and the `PrintManagement` module.
- Remote scripts need admin rights on the target computer; `Invoke-PrinterTestPage` needs WinRM.
- `Backup-DeviceDrivers` must run elevated.

## Usage

Every script has comment-based help:

```powershell
Get-Help .\printers\Find-NetworkPrinter.ps1 -Full
```

Find printers in part of a subnet and keep the ones running out of toner:

```powershell
.\printers\Find-NetworkPrinter.ps1 -Subnet 192.0.2 -Range 1-100 |
    Where-Object TonerPercent -lt 15 |
    Format-Table IPAddress, Name, Model, Supply, TonerPercent
```

```text
IPAddress   Name        Model                          Supply                     TonerPercent
---------   ----        -----                          ------                     ------------
192.0.2.21  prn-floor2  Kyocera ECOSYS M2540dn         TK-1170                    8
192.0.2.47  prn-acct    HP LaserJet Pro M404dn         Black Cartridge HP 59A     12
```

Pick printers in a searchable grid and restart them (dry run first):

```powershell
.\printers\Find-NetworkPrinter.ps1 -Subnet 192.0.2 -GridView |
    .\printers\Restart-NetworkPrinter.ps1 -WhatIf
```

Remove printers from a remote workstation, choosing them interactively:

```powershell
.\printers\Remove-RemotePrinter.ps1 -ComputerName ws-0123
```

Back up drivers before reinstalling Windows:

```powershell
.\maintenance\Backup-DeviceDrivers.ps1 -Destination D:\Drivers
```

## How the printer scan works

1. A TCP connection to port 9100 is started for every address in the range at once, then all of them are
   awaited with one shared timeout (`-TimeoutMs`, 1.5 s by default). A full /24 takes about that long.
2. Hosts that accepted the connection are queried over SNMP v1. Standard OIDs come from the Printer MIB
   (RFC 3805) and Host Resources MIB.
3. Some vendors expose name or serial number only in their private MIB. For Kyocera, Zebra, HP and Canon
   the vendor OID is tried first and the standard one is used as a fallback.

## Limitations

- IPv4 /24 ranges only; SNMP v1/v2c communities, no SNMP v3.
- Only the first marker supply is read (black toner on most devices). Color printers report more supplies.
- Toner percentage is empty when the device reports special values (`-2` unknown, `-3` some remaining).
- `Remove-RemotePrinter` sees printers installed for the computer; per-user connections of other users are not visible remotely.

## History

This repository was previously named `PowerShell`. Old scripts and their replacements:

| Old file | Now |
|---|---|
| `Net_Print_finder_ver2`, `Net_Printer_Finder`, `Extended_search_for_printers_with_repetition`, `Network_Printer_Info` | `printers/Find-NetworkPrinter.ps1` |
| `Delete_selected_network_printer` | `printers/Remove-RemotePrinter.ps1` |
| `Test_Page_network_Printer` | `printers/Invoke-PrinterTestPage.ps1` |
| `Reboot_printers_HP_Kyocera` | `printers/Restart-NetworkPrinter.ps1` |
| `Script BackUp Drivers` | `maintenance/Backup-DeviceDrivers.ps1` |

## License

[MIT](LICENSE)
