<#
.SYNOPSIS
    Discovers network printers in an IPv4 range and reads their details over SNMP.

.DESCRIPTION
    Scans a /24 subnet (or part of it) for hosts that listen on the raw printing port
    (TCP 9100 by default). All connection attempts are started in parallel and then
    awaited with a single shared timeout, so a full /24 takes about one timeout to scan.

    For every host that answers, the script queries the Printer MIB (RFC 3805) and the
    Host Resources MIB over SNMP v1: model, name, serial number, page counter, supply
    description and toner level. Some vendors expose name or serial number only in their
    private MIB, so vendor-specific OIDs are tried first and the standard OIDs are used
    as a fallback.

    The script is read-only: it only opens TCP connections and sends SNMP GET requests.

.PARAMETER Subnet
    First three octets of the network to scan, for example 192.0.2.

.PARAMETER Range
    Host part range to scan, in the form "start-end". Default: 1-254.

.PARAMETER Port
    TCP port used to detect printers. Default: 9100 (raw / JetDirect).

.PARAMETER TimeoutMs
    How long to wait for all TCP connections, in milliseconds. Default: 1500.

.PARAMETER Community
    SNMP v1 read community. Default: public.

.PARAMETER Brief
    Return only IPAddress, Name and Model.

.PARAMETER GridView
    Show results in Out-GridView (with search and multi-select) and return the selected rows.

.EXAMPLE
    .\Find-NetworkPrinter.ps1 -Subnet 192.0.2

    Scans 192.0.2.1-254 and returns one object per printer.

.EXAMPLE
    .\Find-NetworkPrinter.ps1 -Subnet 192.0.2 -Range 10-50 -GridView

    Scans 192.0.2.10-50 and shows the result in a searchable grid.

.EXAMPLE
    .\Find-NetworkPrinter.ps1 -Subnet 192.0.2 | Where-Object TonerPercent -lt 15 | Export-Csv .\low-toner.csv -NoTypeInformation

    Finds printers with less than 15% toner left.

.NOTES
    Requires Windows: SNMP is queried through the built-in olePrn.OleSNMP COM object.
    Works in Windows PowerShell 5.1 and PowerShell 7.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^(\d{1,3})\.(\d{1,3})\.(\d{1,3})$')]
    [string]$Subnet,

    [ValidatePattern('^\d{1,3}-\d{1,3}$')]
    [string]$Range = '1-254',

    [ValidateRange(1, 65535)]
    [int]$Port = 9100,

    [ValidateRange(100, 60000)]
    [int]$TimeoutMs = 1500,

    [string]$Community = 'public',

    [switch]$Brief,

    [switch]$GridView
)

Set-StrictMode -Version Latest

# Standard OIDs: Host Resources MIB, SNMPv2-MIB and Printer MIB (first device / first supply).
$StandardOid = @{
    Model        = '.1.3.6.1.2.1.25.3.2.1.3.1'    # hrDeviceDescr
    Name         = '.1.3.6.1.2.1.1.5.0'           # sysName
    SerialNumber = '.1.3.6.1.2.1.43.5.1.1.17.1'   # prtGeneralSerialNumber
    PageCount    = '.1.3.6.1.2.1.43.10.2.1.4.1.1' # prtMarkerLifeCount
    Supply       = '.1.3.6.1.2.1.43.11.1.1.6.1.1' # prtMarkerSuppliesDescription
    TonerLevel   = '.1.3.6.1.2.1.43.11.1.1.9.1.1' # prtMarkerSuppliesLevel
    TonerMax     = '.1.3.6.1.2.1.43.11.1.1.8.1.1' # prtMarkerSuppliesMaxCapacity
}

# Vendor-specific OIDs, matched against the model string. Tried before the standard ones.
$VendorOid = @(
    @{ Match = '*ECOSYS*';      Oid = @{ Name = '.1.3.6.1.4.1.1347.40.10.1.1.5.1' } }                      # Kyocera
    @{ Match = '*Zebra*';       Oid = @{ SerialNumber = '.1.3.6.1.4.1.10642.200.19.5.0'
                                         PageCount    = '.1.3.6.1.4.1.10642.200.17.3.0' } }                # Zebra
    @{ Match = '*HP LaserJet*'; Oid = @{ SerialNumber = '.1.3.6.1.4.1.11.2.3.9.4.2.1.1.3.3.0' } }          # HP
    @{ Match = '*Canon*';       Oid = @{ SerialNumber = '.1.3.6.1.4.1.1602.1.2.1.4.0' } }                  # Canon
)

function Get-SnmpValue {
    param($Session, [string[]]$Oid)
    foreach ($o in $Oid) {
        if (-not $o) { continue }
        try {
            $value = $Session.Get($o)
            if ($null -ne $value -and "$value" -ne '') { return $value }
        }
        catch {
            # OID not supported by this device - try the next one.
        }
    }
    return $null
}

function Find-OpenPort {
    param([string[]]$Address, [int]$Port, [int]$TimeoutMs)

    $pending = foreach ($ip in $Address) {
        $client = New-Object System.Net.Sockets.TcpClient
        [PSCustomObject]@{ IPAddress = $ip; Client = $client; Task = $client.ConnectAsync($ip, $Port) }
    }

    # One shared deadline for all connections instead of a fixed sleep or a per-host delay.
    $deadline = [DateTime]::UtcNow.AddMilliseconds($TimeoutMs)
    foreach ($p in $pending) {
        $left = [int][Math]::Max(0, ($deadline - [DateTime]::UtcNow).TotalMilliseconds)
        try { [void]$p.Task.Wait($left) } catch { }
        if ($p.Task.Status -eq 'RanToCompletion' -and $p.Client.Connected) { $p.IPAddress }
        $p.Client.Dispose()
    }
}

if (@($Subnet -split '\.' | Where-Object { [int]$_ -gt 255 }).Count) {
    throw "Invalid subnet '$Subnet'."
}

$start, $end = $Range -split '-' | ForEach-Object { [int]$_ }
if ($start -lt 1 -or $end -gt 254 -or $start -gt $end) {
    throw "Invalid range '$Range'. Use start-end within 1-254."
}

$addresses = $start..$end | ForEach-Object { "$Subnet.$_" }
Write-Verbose "Probing $($addresses.Count) addresses on TCP $Port (timeout $TimeoutMs ms)"
$found = @(Find-OpenPort -Address $addresses -Port $Port -TimeoutMs $TimeoutMs)
Write-Verbose "Port $Port is open on $($found.Count) host(s)"

$results = New-Object System.Collections.Generic.List[object]
$i = 0
foreach ($ip in $found) {
    $i++
    Write-Progress -Activity 'Reading printer details over SNMP' -Status $ip -PercentComplete ($i / $found.Count * 100)

    $snmp = New-Object -ComObject olePrn.OleSNMP
    try {
        $snmp.Open($ip, $Community, 1, 1000)

        $model = Get-SnmpValue $snmp $StandardOid.Model
        $vendor = @{}
        foreach ($v in $VendorOid) {
            if ($model -like $v.Match) { $vendor = $v.Oid; break }
        }

        $value = @{}
        foreach ($key in 'Name', 'SerialNumber', 'PageCount', 'Supply', 'TonerLevel', 'TonerMax') {
            $value[$key] = Get-SnmpValue $snmp @($vendor[$key], $StandardOid[$key])
        }
    }
    catch {
        Write-Warning "$ip : SNMP query failed ($($_.Exception.Message))"
        continue
    }
    finally {
        try { $snmp.Close() } catch { }
    }

    # Negative supply levels are special values in the Printer MIB (-2 unknown, -3 "some remaining").
    $level = $value.TonerLevel -as [int]
    $max = $value.TonerMax -as [int]
    $percent = $null
    if ($max -gt 0 -and $level -ge 0) {
        $percent = [Math]::Round($level / $max * 100)
    }

    $results.Add([PSCustomObject]@{
        IPAddress    = $ip
        Name         = $value.Name
        Model        = $model
        SerialNumber = $value.SerialNumber
        PageCount    = $value.PageCount
        Supply       = $value.Supply
        TonerLevel   = $value.TonerLevel
        TonerMax     = $value.TonerMax
        TonerPercent = $percent
    })
}
Write-Progress -Activity 'Reading printer details over SNMP' -Completed

$output = $results
if ($Brief) { $output = $results | Select-Object IPAddress, Name, Model }

if ($GridView) {
    $output | Out-GridView -Title "Printers in $Subnet.$Range" -PassThru
}
else {
    $output
}
