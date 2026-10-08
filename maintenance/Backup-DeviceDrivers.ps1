<#
.SYNOPSIS
    Exports all third-party drivers from the running Windows installation.

.DESCRIPTION
    Uses Export-WindowsDriver (the DISM PowerShell module, same as
    "dism /online /export-driver") to copy every third-party driver package from the
    driver store into a destination folder. Useful before reinstalling Windows or
    replacing a disk: the folder can later be fed to "pnputil /add-driver *.inf /subdirs /install".

    Supports -WhatIf.

.PARAMETER Destination
    Target folder. Created if missing.
    Default: C:\DriverBackup\<COMPUTERNAME>-<yyyyMMdd>.

.PARAMETER PickFolder
    Show a folder picker instead of using -Destination.

.EXAMPLE
    .\Backup-DeviceDrivers.ps1

    Exports drivers to C:\DriverBackup\<COMPUTERNAME>-<yyyyMMdd>.

.EXAMPLE
    .\Backup-DeviceDrivers.ps1 -Destination D:\Drivers -WhatIf

.NOTES
    Run from an elevated PowerShell session.
#>
#Requires -RunAsAdministrator
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [string]$Destination = (Join-Path "$env:SystemDrive\DriverBackup" ("{0}-{1:yyyyMMdd}" -f $env:COMPUTERNAME, (Get-Date))),

    [switch]$PickFolder
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if ($PickFolder) {
    Add-Type -AssemblyName System.Windows.Forms
    $dialog = New-Object System.Windows.Forms.FolderBrowserDialog
    $dialog.Description = 'Select a folder for the driver backup'
    if ($dialog.ShowDialog() -ne [System.Windows.Forms.DialogResult]::OK) {
        Write-Warning 'Cancelled by user.'
        return
    }
    $Destination = $dialog.SelectedPath
}

if (-not $PSCmdlet.ShouldProcess($Destination, 'Export third-party drivers')) { return }

if (-not (Test-Path -LiteralPath $Destination)) {
    New-Item -ItemType Directory -Path $Destination | Out-Null
}

Write-Verbose "Exporting drivers to $Destination"
$drivers = @(Export-WindowsDriver -Online -Destination $Destination)

$drivers |
    Group-Object ClassName |
    Sort-Object Count -Descending |
    Select-Object @{ n = 'Class'; e = { $_.Name } }, Count |
    Format-Table -AutoSize |
    Out-String |
    Write-Verbose

[PSCustomObject]@{
    ComputerName = $env:COMPUTERNAME
    Destination  = $Destination
    DriverCount  = $drivers.Count
    SizeMB       = [Math]::Round((Get-ChildItem -LiteralPath $Destination -Recurse -File | Measure-Object Length -Sum).Sum / 1MB, 1)
}
