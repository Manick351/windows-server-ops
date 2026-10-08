<#
.SYNOPSIS
    Identifies hosts behind IP addresses that cause failed logons or account lockouts.

.DESCRIPTION
    Domain controller events (4625, 4771, 4776) often contain only a client IP address. This script
    tries to turn those addresses into hosts:

      1. reverse DNS (PTR) for every address;
      2. forward-resolves every computer account in AD and matches the addresses
         (finds hosts whose PTR record is missing or stale);
      3. optionally probes a few TCP ports to guess the OS (SSH only -> Linux; RDP/WinRM -> Windows).

    Read-only, no ActiveDirectory module required.

.PARAMETER IPAddress
    One or more IPv4 addresses from the security events.

.PARAMETER ScanPorts
    Probe TCP 22, 445, 3389, 5985, 443 on each address.

.EXAMPLE
    .\Resolve-LockoutSource.ps1 -IPAddress 10.0.0.15, 10.0.0.42 -ScanPorts
#>
#Requires -Version 5.1
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
    [ValidatePattern('^\d{1,3}(\.\d{1,3}){3}$')]
    [string[]]$IPAddress,

    [switch]$ScanPorts
)

begin {
    Set-StrictMode -Version Latest
    $targets = New-Object System.Collections.Generic.List[string]
}

process { foreach ($ip in $IPAddress) { $targets.Add($ip) } }

end {
    $result = @{}
    foreach ($ip in $targets) {
        $result[$ip] = [ordered]@{ IPAddress = $ip; Ptr = $null; AdComputer = $null; OperatingSystem = $null; Description = $null; OpenPorts = $null; Guess = $null }
    }

    Write-Host '[1] Reverse DNS' -ForegroundColor Cyan
    foreach ($ip in $targets) {
        $name = $null
        try { $name = [System.Net.Dns]::GetHostEntry($ip).HostName } catch { }
        if ($name -and $name -ne $ip) { $result[$ip].Ptr = $name }
        Write-Host ('  {0,-16} -> {1}' -f $ip, $(if ($result[$ip].Ptr) { $result[$ip].Ptr } else { 'no PTR record' })) -ForegroundColor $(if ($result[$ip].Ptr) { 'Green' } else { 'DarkYellow' })
    }

    Write-Host '[2] Matching against computer accounts in AD (forward lookup)' -ForegroundColor Cyan
    $searcher = New-Object System.DirectoryServices.DirectorySearcher([adsi]'')
    $searcher.Filter = '(objectCategory=computer)'
    $searcher.PageSize = 1000
    foreach ($p in 'dNSHostName', 'operatingSystem', 'description') { [void]$searcher.PropertiesToLoad.Add($p) }
    $computers = @($searcher.FindAll())
    Write-Host "  computer objects: $($computers.Count) (resolving all of them can take a few minutes)" -ForegroundColor DarkGray
    $done = 0
    foreach ($c in $computers) {
        $done++
        if ($done % 200 -eq 0) { Write-Progress -Activity 'Resolving computer accounts' -PercentComplete ($done / $computers.Count * 100) }
        if (-not $c.Properties['dnshostname'].Count) { continue }
        $hostName = [string]$c.Properties['dnshostname'][0]
        $addresses = @()
        try { $addresses = @([System.Net.Dns]::GetHostAddresses($hostName) | ForEach-Object { $_.IPAddressToString }) } catch { }
        foreach ($a in $addresses) {
            if (-not $result.ContainsKey($a)) { continue }
            $result[$a].AdComputer = $hostName
            if ($c.Properties['operatingsystem'].Count) { $result[$a].OperatingSystem = [string]$c.Properties['operatingsystem'][0] }
            if ($c.Properties['description'].Count) { $result[$a].Description = [string]$c.Properties['description'][0] }
            Write-Host ('  FOUND {0,-16} = {1} [{2}] {3}' -f $a, $hostName, $result[$a].OperatingSystem, $result[$a].Description) -ForegroundColor Green
        }
    }
    Write-Progress -Activity 'Resolving computer accounts' -Completed
    $missing = @($targets | Where-Object { -not $result[$_].AdComputer })
    if ($missing) { Write-Host "  not matched: $($missing -join ', ') (not domain-joined, different DNS name, or stale record)" -ForegroundColor DarkYellow }

    if ($ScanPorts) {
        Write-Host '[3] Open ports (OS / role hint)' -ForegroundColor Cyan
        foreach ($ip in $targets) {
            $open = foreach ($port in 22, 445, 3389, 5985, 443) {
                $client = New-Object System.Net.Sockets.TcpClient
                try {
                    $async = $client.BeginConnect($ip, $port, $null, $null)
                    if ($async.AsyncWaitHandle.WaitOne(700) -and $client.Connected) { $port }
                }
                catch { }
                finally { $client.Close() }
            }
            $open = @($open)
            $guess = if ($open -contains 22 -and $open -notcontains 3389 -and $open -notcontains 5985) { 'Linux / appliance' }
                     elseif ($open -contains 3389 -or $open -contains 5985) { 'Windows' } else { 'unknown' }
            $result[$ip].OpenPorts = $open -join ','
            $result[$ip].Guess = $guess
            Write-Host ('  {0,-16} ports: {1,-18} likely: {2}' -f $ip, $result[$ip].OpenPorts, $guess)
        }
    }

    Write-Host ''
    Write-Host 'Next steps: on Windows check scheduled tasks, services, mapped drives and Credential Manager running as the account;' -ForegroundColor Cyan
    Write-Host 'on Linux check SSSD/Kerberos keytabs, cron jobs, mounts (cifs) and stored application credentials.' -ForegroundColor Cyan

    foreach ($ip in $targets) { [PSCustomObject]$result[$ip] }
}
