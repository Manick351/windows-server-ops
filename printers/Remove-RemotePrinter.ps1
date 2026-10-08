<#
.SYNOPSIS
    Removes printers from a remote Windows computer.

.DESCRIPTION
    Lists the printers installed on a remote computer and removes the ones given in -Name.
    If -Name is omitted, the printers are shown in Out-GridView and the selected ones are removed.

    Names are compared exactly (not as wildcards or regular expressions), so selecting
    "HP LaserJet" never removes "HP LaserJet (Copy 1)".

    Supports -WhatIf and asks for confirmation before each removal unless -Confirm:$false is used.

.PARAMETER ComputerName
    Remote computer to manage.

.PARAMETER Name
    Exact printer names to remove. If omitted, an interactive picker is shown.

.EXAMPLE
    .\Remove-RemotePrinter.ps1 -ComputerName ws-0123 -WhatIf

    Shows a picker and reports what would be removed, without removing anything.

.EXAMPLE
    .\Remove-RemotePrinter.ps1 -ComputerName ws-0123 -Name 'Printer-Floor2', 'Printer-Floor3' -Confirm:$false

.NOTES
    Requires the PrintManagement module (Windows 8 / Server 2012 and later) and admin rights
    on the remote computer. Per-user printer connections of other users are not visible remotely.
#>
[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [Parameter(Mandatory = $true)]
    [string]$ComputerName,

    [string[]]$Name
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$installed = @(Get-Printer -ComputerName $ComputerName)
if (-not $installed) {
    Write-Warning "No printers found on $ComputerName."
    return
}

if ($Name) {
    $targets = @($installed | Where-Object { $Name -contains $_.Name })
    $installedNames = @($installed | ForEach-Object { $_.Name })
    $missing = @($Name | Where-Object { $installedNames -notcontains $_ })
    foreach ($m in $missing) { Write-Warning "Printer '$m' not found on $ComputerName." }
}
else {
    $targets = @($installed |
        Select-Object Name, DriverName, PortName, Shared, Type |
        Out-GridView -Title "Select printers to remove from $ComputerName" -OutputMode Multiple)
}

foreach ($printer in $targets) {
    if ($PSCmdlet.ShouldProcess("$ComputerName", "Remove printer '$($printer.Name)'")) {
        try {
            Remove-Printer -ComputerName $ComputerName -Name $printer.Name
            [PSCustomObject]@{ ComputerName = $ComputerName; Printer = $printer.Name; Result = 'Removed' }
        }
        catch {
            Write-Warning "Failed to remove '$($printer.Name)': $($_.Exception.Message)"
            [PSCustomObject]@{ ComputerName = $ComputerName; Printer = $printer.Name; Result = 'Failed' }
        }
    }
}
