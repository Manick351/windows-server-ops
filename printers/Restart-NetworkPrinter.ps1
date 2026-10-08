<#
.SYNOPSIS
    Power-cycles network printers over SNMP.

.DESCRIPTION
    Sets prtGeneralReset (Printer MIB, RFC 3805, OID 1.3.6.1.2.1.43.5.1.1.3.1) to
    powerCycleReset (4). Most HP and Kyocera devices accept it; others may ignore the
    request or require a write community different from "public".

    Supports -WhatIf and asks for confirmation unless -Confirm:$false is used.

.PARAMETER IPAddress
    One or more printer addresses or host names. Accepts pipeline input, including the
    IPAddress property of objects returned by Find-NetworkPrinter.ps1.

.PARAMETER Community
    SNMP v1 write community. Default: public.

.EXAMPLE
    .\Restart-NetworkPrinter.ps1 -IPAddress 192.0.2.25 -WhatIf

.EXAMPLE
    .\Find-NetworkPrinter.ps1 -Subnet 192.0.2 -GridView | .\Restart-NetworkPrinter.ps1 -Community private

    Pick printers in a grid and restart the selected ones.

.NOTES
    Requires Windows: SNMP is sent through the built-in olePrn.OleSNMP COM object.
#>
[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
    [string[]]$IPAddress,

    [string]$Community = 'public'
)

begin {
    Set-StrictMode -Version Latest
    $resetOid = '.1.3.6.1.2.1.43.5.1.1.3.1'
    $powerCycleReset = 4
}

process {
    foreach ($ip in $IPAddress) {
        if (-not $PSCmdlet.ShouldProcess($ip, 'Power-cycle printer via SNMP')) { continue }

        $snmp = New-Object -ComObject olePrn.OleSNMP
        try {
            $snmp.Open($ip, $Community, 1, 2000)
            $snmp.Set($resetOid, $powerCycleReset)
            [PSCustomObject]@{ IPAddress = $ip; Result = 'ResetSent' }
        }
        catch {
            Write-Warning "$ip : reset failed ($($_.Exception.Message))"
            [PSCustomObject]@{ IPAddress = $ip; Result = 'Failed' }
        }
        finally {
            try { $snmp.Close() } catch { }
        }
    }
}
