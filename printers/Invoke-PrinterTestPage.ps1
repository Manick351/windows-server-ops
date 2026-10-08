<#
.SYNOPSIS
    Prints a Windows test page on printers of a remote computer.

.DESCRIPTION
    Calls the PrintTestPage method of Win32_Printer through CIM. If -Name is omitted,
    the printers are shown in Out-GridView and the test page is sent to the selected ones.

    Supports -WhatIf.

.PARAMETER ComputerName
    Computer where the printers are installed. Default: local computer.

.PARAMETER Name
    Exact printer names. If omitted, an interactive picker is shown.

.EXAMPLE
    .\Invoke-PrinterTestPage.ps1 -ComputerName ws-0123

.EXAMPLE
    .\Invoke-PrinterTestPage.ps1 -ComputerName ws-0123 -Name 'Printer-Floor2'

.NOTES
    Requires WinRM (CIM over WS-Man) access to the remote computer.
#>
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [string]$ComputerName = $env:COMPUTERNAME,

    [string[]]$Name
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$session = New-CimSession -ComputerName $ComputerName
try {
    $printers = @(Get-CimInstance -CimSession $session -ClassName Win32_Printer)

    if ($Name) {
        $targets = @($printers | Where-Object { $Name -contains $_.Name })
    }
    else {
        $picked = @($printers |
            Select-Object Name, DriverName, PortName, Shared |
            Out-GridView -Title "Select printers on $ComputerName for a test page" -OutputMode Multiple)
        $pickedNames = @($picked | ForEach-Object { $_.Name })
        $targets = @($printers | Where-Object { $pickedNames -contains $_.Name })
    }

    foreach ($printer in $targets) {
        if (-not $PSCmdlet.ShouldProcess("$ComputerName\$($printer.Name)", 'Print test page')) { continue }

        $result = Invoke-CimMethod -InputObject $printer -MethodName PrintTestPage
        [PSCustomObject]@{
            ComputerName = $ComputerName
            Printer      = $printer.Name
            Result       = if ($result.ReturnValue -eq 0) { 'Sent' } else { 'Failed' }
            ReturnValue  = $result.ReturnValue
        }
    }
}
finally {
    Remove-CimSession -CimSession $session
}
