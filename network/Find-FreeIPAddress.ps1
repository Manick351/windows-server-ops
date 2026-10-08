<#
.SYNOPSIS
    Finds free IPv4 addresses in a /24 (or in given CIDR subnets) before you assign one to a new server.

.DESCRIPTION
    "Free" has to mean more than "does not answer ping". Every address is checked in parallel
    (runspace pool) for:

      - ICMP echo, two attempts, with TTL (TTL > 128 usually means a router or firewall, 65-128 Windows, <= 64 Linux);
      - reverse DNS (PTR) with a timeout;
      - presence in this host's ARP / neighbor cache (works for the local segment);
      - presence in an inventory you pass with -KnownAddress (CMDB, IPAM, DHCP export) and -RetiredAddress.

    Subnet awareness: with -KnownSubnet (for example a gateway CIDR copied from a cloud portal,
    192.0.2.161/29) or from this host's own interfaces, the network and broadcast addresses are marked
    as reserved and the configured gateway is verified (answers? looks like a router?). Routers found
    outside known subnets are reported with the largest mask they can belong to.

    Status values: Free, Check (no answer, but a PTR record or retired inventory entry remains),
    Busy, Gateway, Reserved (network / broadcast, real or likely), Alarm (gateway not answering or not a router).

.PARAMETER Subnet
    First three octets, for example 192.0.2.

.PARAMETER Range
    Host part range "start-end" within the /24. Default: 1-254.

.PARAMETER KnownSubnet
    CIDR subnets inside the /24. A host address (not network/broadcast) is treated as the gateway.

.PARAMETER OnlyKnownSubnets
    Scan only the addresses of -KnownSubnet instead of -Range.

.PARAMETER KnownAddress
    Addresses that are assigned in your inventory: treated as busy even if they do not answer.

.PARAMETER RetiredAddress
    Addresses of retired inventory records: shown as Check if they do not answer.

.PARAMETER ThrottleLimit
    Parallel probes. Default: 64.

.PARAMETER TimeoutMs
    Ping timeout per attempt. Default: 800.

.PARAMETER OnlyFree
    Return only Free addresses.

.PARAMETER GridView
    Show the result in Out-GridView.

.EXAMPLE
    .\Find-FreeIPAddress.ps1 -Subnet 192.0.2 -OnlyFree

.EXAMPLE
    .\Find-FreeIPAddress.ps1 -Subnet 192.0.2 -KnownSubnet 192.0.2.161/29 -OnlyKnownSubnets

.EXAMPLE
    $cmdb = Import-Csv .\cmdb-export.csv
    .\Find-FreeIPAddress.ps1 -Subnet 10.0.0 -Range 100-199 `
        -KnownAddress ($cmdb | Where-Object Status -ne 'Retired').IPAddress `
        -RetiredAddress ($cmdb | Where-Object Status -eq 'Retired').IPAddress -GridView
#>
#Requires -Version 5.1
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^\d{1,3}\.\d{1,3}\.\d{1,3}$')]
    [string]$Subnet,

    [ValidatePattern('^\d{1,3}-\d{1,3}$')]
    [string]$Range = '1-254',

    [string[]]$KnownSubnet = @(),

    [switch]$OnlyKnownSubnets,

    [string[]]$KnownAddress = @(),

    [string[]]$RetiredAddress = @(),

    [ValidateRange(1, 256)]
    [int]$ThrottleLimit = 64,

    [ValidateRange(100, 10000)]
    [int]$TimeoutMs = 800,

    [switch]$OnlyFree,

    [switch]$GridView
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$routerMinTtl = 129   # initial TTL 255 is typical for network devices

#region IP math

function ConvertTo-IpNumber {
    param([string]$Ip)
    $bytes = [System.Net.IPAddress]::Parse($Ip).GetAddressBytes()
    [Array]::Reverse($bytes)
    return [uint64][BitConverter]::ToUInt32($bytes, 0)
}

function ConvertFrom-IpNumber {
    param([uint64]$Number)
    $bytes = [BitConverter]::GetBytes([uint32]$Number)
    [Array]::Reverse($bytes)
    return (New-Object System.Net.IPAddress (, $bytes)).ToString()
}

function Get-SubnetBounds {
    param([uint64]$Address, [int]$Prefix)
    $size = [uint64]1 -shl (32 - $Prefix)
    $network = [uint64][Math]::Floor($Address / $size) * $size
    return @{ Network = $network; Broadcast = $network + $size - 1 }
}

#endregion

if (@($Subnet -split '\.' | Where-Object { [int]$_ -gt 255 }).Count) { throw "Invalid subnet '$Subnet'." }
$base = ConvertTo-IpNumber "$Subnet.0"

# Known subnets: from the parameter and from this host's interfaces (Windows only).
$subnets = New-Object System.Collections.Generic.List[object]
foreach ($token in $KnownSubnet) {
    if ($token -notmatch '^(\d{1,3}(?:\.\d{1,3}){3})/(\d{1,2})$') { throw "Cannot parse '$token' (expected 192.0.2.161/29)." }
    $prefix = [int]$Matches[2]
    if ($prefix -lt 8 -or $prefix -gt 30) { throw "'$token': prefix must be /8../30." }
    $address = ConvertTo-IpNumber $Matches[1]
    $b = Get-SubnetBounds $address $prefix
    if ($b.Broadcast -lt $base -or $b.Network -gt $base + 255) { throw "'$token' does not overlap $Subnet.0/24." }
    $gateway = if ($address -ne $b.Network -and $address -ne $b.Broadcast) { $address } else { $null }
    $subnets.Add([PSCustomObject]@{ Network = $b.Network; Broadcast = $b.Broadcast; Prefix = $prefix; Gateway = $gateway; Source = 'given' })
}
if (Get-Command Get-NetIPAddress -ErrorAction SilentlyContinue) {
    foreach ($a in (Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue)) {
        if ($a.PrefixLength -lt 8 -or $a.PrefixLength -gt 30) { continue }
        $b = Get-SubnetBounds (ConvertTo-IpNumber $a.IPAddress) $a.PrefixLength
        if ($b.Broadcast -lt $base -or $b.Network -gt $base + 255) { continue }
        if ($subnets | Where-Object { $_.Network -eq $b.Network -and $_.Prefix -eq $a.PrefixLength }) { continue }
        $gateway = $null
        $route = Get-NetRoute -InterfaceIndex $a.InterfaceIndex -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($route -and $route.NextHop -ne '0.0.0.0') {
            $g = ConvertTo-IpNumber $route.NextHop
            if ($g -ge $b.Network -and $g -le $b.Broadcast) { $gateway = $g }
        }
        $subnets.Add([PSCustomObject]@{ Network = $b.Network; Broadcast = $b.Broadcast; Prefix = $a.PrefixLength; Gateway = $gateway; Source = 'this host interface' })
    }
}

# Octets to scan
if ($OnlyKnownSubnets) {
    $given = @($subnets | Where-Object Source -eq 'given')
    if (-not $given) { throw '-OnlyKnownSubnets needs -KnownSubnet.' }
    $octets = @($given | ForEach-Object {
            $lo = [int][Math]::Max([int64]$_.Network - [int64]$base, 0)
            $hi = [int][Math]::Min([int64]$_.Broadcast - [int64]$base, 255)
            $lo..$hi
        } | Sort-Object -Unique)
}
else {
    $from, $to = $Range -split '-' | ForEach-Object { [int]$_ }
    if ($from -gt $to -or $to -gt 255) { throw "Invalid range '$Range'." }
    $octets = @($from..$to)
}

$arp = @()
if (Get-Command Get-NetNeighbor -ErrorAction SilentlyContinue) {
    $arp = @(Get-NetNeighbor -AddressFamily IPv4 -ErrorAction SilentlyContinue |
        Where-Object { $_.IPAddress -like "$Subnet.*" -and $_.State -notin 'Unreachable', 'Incomplete' -and $_.LinkLayerAddress -notin 'ff-ff-ff-ff-ff-ff', '00-00-00-00-00-00', '' } |
        ForEach-Object IPAddress)
}

$probe = {
    param([string]$Ip, [int]$Octet, [int]$TimeoutMs)
    $alive = $false; $ttl = $null; $rtt = $null; $unreachable = $null
    $ping = New-Object System.Net.NetworkInformation.Ping
    try {
        for ($i = 0; $i -lt 2 -and -not $alive; $i++) {
            try {
                $reply = $ping.Send($Ip, $TimeoutMs)
                $from = if ($reply.Address) { $reply.Address.ToString() } else { '' }
                if ($reply.Status -eq 'Success' -and $from -eq $Ip) {
                    $alive = $true; $rtt = $reply.RoundtripTime
                    if ($reply.Options) { $ttl = $reply.Options.Ttl }
                }
                elseif ($reply.Status -in 'DestinationHostUnreachable', 'DestinationNetworkUnreachable') {
                    $unreachable = "$($reply.Status)" + $(if ($from -and $from -ne $Ip) { " (from $from)" } else { '' })
                }
            }
            catch { }
        }
    }
    finally { $ping.Dispose() }

    $ptr = $null
    try {
        $task = [System.Net.Dns]::GetHostEntryAsync($Ip)
        if ($task.Wait(2500) -and $task.Result.HostName -and $task.Result.HostName -ne $Ip) { $ptr = $task.Result.HostName }
    }
    catch { }
    [PSCustomObject]@{ IP = $Ip; Octet = $Octet; Alive = $alive; TTL = $ttl; Rtt = $rtt; Ptr = $ptr; Unreachable = $unreachable }
}

Write-Host "Scanning $Subnet.$($octets[0])-$($octets[-1]) ($($octets.Count) addresses, $ThrottleLimit threads)..." -ForegroundColor Cyan
$pool = [runspacefactory]::CreateRunspacePool(1, $ThrottleLimit)
$pool.Open()
$jobs = foreach ($o in $octets) {
    $ps = [powershell]::Create()
    $ps.RunspacePool = $pool
    [void]$ps.AddScript($probe).AddArgument("$Subnet.$o").AddArgument($o).AddArgument($TimeoutMs)
    [PSCustomObject]@{ Shell = $ps; Handle = $ps.BeginInvoke() }
}
$probes = @{}
$done = 0
foreach ($j in $jobs) {
    $r = $j.Shell.EndInvoke($j.Handle) | Select-Object -First 1
    $j.Shell.Dispose()
    $probes[[int]$r.Octet] = $r
    $done++
    Write-Progress -Activity 'Probing addresses' -Status "$done / $($octets.Count)" -PercentComplete ($done / $octets.Count * 100)
}
Write-Progress -Activity 'Probing addresses' -Completed
$pool.Close(); $pool.Dispose()

# Roles of addresses: network, broadcast, gateway, routers
$role = @{}
$subnetLabel = @{}
$warnings = New-Object System.Collections.Generic.List[string]
$routers = @($probes.Values | Where-Object { $_.Alive -and $_.TTL -ge $routerMinTtl } | ForEach-Object { [int]$_.Octet } | Sort-Object)

foreach ($s in $subnets) {
    $label = '{0}/{1}' -f (ConvertFrom-IpNumber $s.Network), $s.Prefix
    $lo = [int][Math]::Max([int64]$s.Network - [int64]$base, 0)
    $hi = [int][Math]::Min([int64]$s.Broadcast - [int64]$base, 255)
    for ($o = $lo; $o -le $hi; $o++) { $subnetLabel[$o] = $label }
    if ($s.Network -ge $base) { $role[[int]($s.Network - $base)] = @{ Kind = 'Reserved'; Status = 'NETWORK'; Note = "network address of $label ($($s.Source))" } }
    if ($s.Broadcast -le $base + 255) { $role[[int]($s.Broadcast - $base)] = @{ Kind = 'Reserved'; Status = 'BROADCAST'; Note = "broadcast of $label ($($s.Source))" } }
    $inside = @($routers | Where-Object { $_ -ge $lo -and $_ -le $hi })
    foreach ($g in $inside) { $role[$g] = @{ Kind = 'Gateway'; Status = 'GATEWAY?'; Note = "network device in $label, probably the gateway" } }

    if ($null -ne $s.Gateway) {
        $gText = ConvertFrom-IpNumber $s.Gateway
        $go = [int64]$s.Gateway - [int64]$base
        if (-not $probes.ContainsKey([int]$go)) { $warnings.Add("Gateway $gText of $label is outside the scanned range."); continue }
        $gp = $probes[[int]$go]
        $others = @($inside | Where-Object { $_ -ne $go })
        if ($gp.Alive -and $null -eq $gp.TTL) {
            $role[[int]$go] = @{ Kind = 'Gateway'; Status = 'GATEWAY'; Note = "gateway of $label, answers (TTL not available on this platform)" }
        }
        elseif ($gp.Alive -and $gp.TTL -ge $routerMinTtl) {
            $role[[int]$go] = @{ Kind = 'Gateway'; Status = 'GATEWAY'; Note = "gateway of $label, answers, TTL $($gp.TTL)" }
        }
        elseif ($gp.Alive) {
            $role[[int]$go] = @{ Kind = 'Alarm'; Status = 'GATEWAY NOT ROUTER?'; Note = "configured as gateway of $label but TTL $($gp.TTL) looks like a server" }
            $warnings.Add("Gateway $gText answers with TTL $($gp.TTL): looks like a server, not a router." + $(if ($others) { " Network device(s) in the subnet: $(($others | ForEach-Object { ".$_" }) -join ', ')." } else { '' }))
        }
        else {
            $role[[int]$go] = @{ Kind = 'Alarm'; Status = 'GATEWAY DOWN'; Note = "configured as gateway of $label, does not answer" }
            $warnings.Add("Gateway $gText of $label does not answer." + $(if ($others) { " Network device(s) that answer: $(($others | ForEach-Object { ".$_" }) -join ', ')." } else { '' }))
        }
    }
}

foreach ($g in $routers) {
    if ($role.ContainsKey($g)) { continue }
    if ($subnets | Where-Object { ($base + $g) -ge $_.Network -and ($base + $g) -le $_.Broadcast }) { continue }
    # Largest block where the router is the first or last usable address and no other router or known subnet lives.
    $bound = $null
    foreach ($size in 256, 128, 64, 32, 16, 8, 4) {
        $n = [int]([Math]::Floor($g / $size) * $size); $b = $n + $size - 1
        if (-not ($g -eq $n + 1 -or $g -eq $b - 1)) { continue }
        if ($routers | Where-Object { $_ -ne $g -and $_ -ge $n -and $_ -le $b }) { continue }
        if ($subnets | Where-Object { $_.Network -le ($base + $b) -and $_.Broadcast -ge ($base + $n) }) { continue }
        $bound = @{ Low = $n; High = $b; Prefix = 32 - [int][Math]::Log($size, 2) }
        break
    }
    $boundText = if ($bound) { "mask /$($bound.Prefix) or smaller: .$($bound.Low)-.$($bound.High)" } else { 'subnet bounds unknown' }
    $role[$g] = @{ Kind = 'Gateway'; Status = 'GATEWAY?'; Note = "network device (TTL $($probes[$g].TTL)), likely a gateway; $boundText. Pass -KnownSubnet for exact bounds." }
    if (($g - 1) % 4 -eq 0 -and -not $role.ContainsKey($g - 1)) {
        $role[$g - 1] = @{ Kind = 'Reserved'; Status = 'NETWORK?'; Note = "likely network address: gateway .$g is usually the first host ($boundText)"; Guess = $true }
    }
    elseif (($g + 2) % 4 -eq 0 -and $g -le 254 -and -not $role.ContainsKey($g + 1)) {
        $role[$g + 1] = @{ Kind = 'Reserved'; Status = 'BROADCAST?'; Note = "likely broadcast: gateway .$g is usually the last host ($boundText)"; Guess = $true }
    }
}

# Final classification
$known = @($KnownAddress | Where-Object { $_ })
$retired = @($RetiredAddress | Where-Object { $_ })
$results = foreach ($p in ($probes.Values | Sort-Object Octet)) {
    $o = [int]$p.Octet
    $inArp = $arp -contains $p.IP
    $inInventory = $known -contains $p.IP
    $busy = $p.Alive -or $inArp -or $inInventory
    $r = $role[$o]
    $isGuess = $r -and $r.ContainsKey('Guess')

    if ($r -and -not ($isGuess -and $busy)) { $kind = $r.Kind; $status = $r.Status }
    elseif ($busy) { $kind = 'Busy'; $status = 'BUSY' }
    elseif ($p.Ptr -or $retired -contains $p.IP) { $kind = 'Check'; $status = 'CHECK' }
    else { $kind = 'Free'; $status = 'FREE' }

    $details = @()
    if ($r) { $details += $r.Note }
    if ($p.Alive) { $details += "ping $($p.Rtt) ms" }
    if ($inArp) { $details += 'in ARP cache' }
    if ($inInventory) { $details += 'in inventory' }
    if ($retired -contains $p.IP) { $details += 'retired inventory record' }
    if ($p.Ptr) { $details += "PTR $($p.Ptr)" }
    if (-not $p.Alive -and $p.Unreachable) { $details += $p.Unreachable }
    if ($kind -eq 'Check') { $details += 'no answer but a DNS/inventory trace remains: clean it up and confirm with the owner first' }

    $ttlHint = if ($null -eq $p.TTL) { '' } elseif ($p.TTL -ge $routerMinTtl) { 'network' } elseif ($p.TTL -gt 64) { 'Windows' } else { 'Linux/Unix' }
    [PSCustomObject]@{
        IPAddress = $p.IP
        Status    = $status
        Kind      = $kind
        Name      = if ($p.Ptr) { ($p.Ptr -split '\.')[0] } else { '' }
        TTL       = $p.TTL
        OSHint    = $ttlHint
        Subnet    = if ($subnetLabel.ContainsKey($o)) { $subnetLabel[$o] } else { '' }
        Detail    = $details -join '; '
    }
}
$results = @($results)

$counts = $results | Group-Object Kind | ForEach-Object { "$($_.Name)=$($_.Count)" }
Write-Host ('Done: ' + ($counts -join ', ')) -ForegroundColor Green
if ($routers) { Write-Host ('Network devices (TTL > 128): ' + (($routers | ForEach-Object { ".$_" }) -join ', ')) }
foreach ($w in $warnings) { Write-Warning $w }

$output = if ($OnlyFree) { $results | Where-Object Kind -eq 'Free' } else { $results }
if ($GridView) { $output | Out-GridView -Title "IP addresses in $Subnet.0/24" -PassThru } else { $output }
