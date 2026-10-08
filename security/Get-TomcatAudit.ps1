<#
.SYNOPSIS
    Inventories Apache Tomcat installations on Windows servers and evaluates exposure to known critical CVEs.

.DESCRIPTION
    Read-only collector for vulnerability remediation work. For every Tomcat instance (found through
    services, Procrun registry and an optional -TomcatHint path) it collects:

      - exact version (from catalina.jar ServerInfo.properties and RELEASE-NOTES), service account and state;
      - JVM path and version, Procrun parameters (secrets masked);
      - server.xml: connectors (port, protocol, address, TLS, AJP secret, HTTP/2 upgrade), hosts, valves, realms;
      - DefaultServlet / WebDAV settings from every web.xml (readonly, allowPartialPut), session managers
        (PersistentManager) from context.xml;
      - users and roles from tomcat-users.xml (names only), deployed webapps, non-standard libraries,
        libraries known as deserialization gadgets in WEB-INF\lib;
      - listening ports, inbound and outbound peers of the Java processes, other web servers (IIS sites);
      - SHA-256 of every file in conf\ (with exactly two servers the configs are compared).

    The summary evaluates each instance against:
      CVE-2020-1938  (Ghostcat, AJP file read/inclusion)          - version + AJP connector exposure
      CVE-2023-44487 (HTTP/2 Rapid Reset DoS)                     - version + HTTP/2 enabled
      CVE-2025-24813 (partial PUT RCE / information disclosure)   - version + DefaultServlet readonly=false
    using fixed versions per branch. A vulnerable version with the feature disabled is reported as such.

    Output: <OutDir>\<server>.json (full data), summary.csv / summary.txt, conf_compare.csv.

.PARAMETER ComputerName
    Servers to audit.

.PARAMETER Local
    Audit the local computer without WinRM.

.PARAMETER TomcatHint
    Extra Tomcat home folder to check when it is not installed as a service.

.PARAMETER OutDir
    Output folder. Default: .\TomcatAudit_<timestamp>.

.PARAMETER Credential
    Optional credential for WinRM.

.EXAMPLE
    .\Get-TomcatAudit.ps1 -ComputerName srv-app-01.contoso.local, srv-app-02.contoso.local

.EXAMPLE
    .\Get-TomcatAudit.ps1 -Local -TomcatHint 'D:\Tomcat 9.0'
#>
#Requires -Version 5.1
[CmdletBinding(DefaultParameterSetName = 'Remote')]
param(
    [Parameter(ParameterSetName = 'Remote', Mandatory = $true)]
    [string[]]$ComputerName,

    [Parameter(ParameterSetName = 'Local', Mandatory = $true)]
    [switch]$Local,

    [string]$TomcatHint = '',

    [string]$OutDir = (Join-Path (Get-Location).Path ('TomcatAudit_{0:yyyyMMdd_HHmm}' -f (Get-Date))),

    [pscredential]$Credential
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# First fixed release per branch. A branch older than all listed ones has no fix (end of life).
$fixedVersions = @{
    'CVE-2020-1938'  = @{ '7.0' = '7.0.100'; '8.5' = '8.5.51'; '9.0' = '9.0.31' }
    'CVE-2023-44487' = @{ '8.5' = '8.5.94'; '9.0' = '9.0.81'; '10.1' = '10.1.14'; '11.0' = '11.0.0' }
    'CVE-2025-24813' = @{ '9.0' = '9.0.99'; '10.1' = '10.1.35'; '11.0' = '11.0.3' }
}

function Get-VersionState {
    # Returns 'fixed', 'vulnerable', 'no fix (EOL branch)' or 'unknown'.
    param([string]$Version, [string]$Cve)
    if ($Version -notmatch '^(\d+)\.(\d+)\.(\d+)') { return 'unknown' }
    $v = [version]"$($Matches[1]).$($Matches[2]).$($Matches[3])"
    $branch = "$($Matches[1]).$($Matches[2])"
    $table = $fixedVersions[$Cve]
    if ($table.ContainsKey($branch)) { if ($v -ge [version]$table[$branch]) { return 'fixed' } else { return 'vulnerable' } }
    $branches = @($table.Keys | ForEach-Object { [version]$_ } | Sort-Object)
    if ([version]$branch -gt $branches[-1]) { return 'fixed' }
    return 'no fix (EOL branch)'
}

$collector = {
    param([string]$Hint)
    $ErrorActionPreference = 'Continue'

    function Hide-Secret([string]$Text) { if (-not $Text) { return $Text }; $Text -replace '(?i)((pass(word)?|secret|pwd|token)[^=\s]*=)\S*', '$1***' }
    function Read-Xml([string]$Path) {
        if (-not (Test-Path -LiteralPath $Path)) { return $null }
        try { $x = New-Object System.Xml.XmlDocument; $x.XmlResolver = $null; $x.Load($Path); return , $x } catch { return $null }
    }
    function Get-NodeText($Node, [string]$Name) { $c = $Node.SelectSingleNode("*[local-name()='$Name']"); if ($c) { $c.InnerText.Trim() } else { '' } }
    function Get-JarEntryText([string]$Jar, [string]$Entry) {
        if (-not (Test-Path -LiteralPath $Jar)) { return $null }
        # Copy first: the running JVM keeps the jar open.
        $tmp = Join-Path $env:TEMP ('jar_' + [guid]::NewGuid().ToString('N') + '.zip')
        try {
            Copy-Item -LiteralPath $Jar -Destination $tmp
            Add-Type -AssemblyName System.IO.Compression.FileSystem
            $zip = [System.IO.Compression.ZipFile]::OpenRead($tmp)
            try {
                $e = $zip.Entries | Where-Object FullName -eq $Entry | Select-Object -First 1
                if ($e) { $sr = New-Object System.IO.StreamReader($e.Open()); try { $sr.ReadToEnd() } finally { $sr.Dispose() } }
            }
            finally { $zip.Dispose() }
        }
        catch { $null }
        finally { Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue }
    }
    function Get-ServletInfo([string]$WebXml) {
        $x = Read-Xml $WebXml
        if (-not $x) { return }
        foreach ($s in $x.SelectNodes("//*[local-name()='servlet']")) {
            $class = Get-NodeText $s 'servlet-class'
            if ($class -notmatch 'DefaultServlet|WebdavServlet') { continue }
            $p = [ordered]@{}
            foreach ($ip in $s.SelectNodes("*[local-name()='init-param']")) { $p[(Get-NodeText $ip 'param-name')] = Get-NodeText $ip 'param-value' }
            [PSCustomObject]@{
                File = $WebXml; Name = Get-NodeText $s 'servlet-name'; Class = $class
                ReadOnly = if ($p.Contains('readonly')) { $p['readonly'] } else { 'default (true)' }
                AllowPartialPut = if ($p.Contains('allowPartialPut')) { $p['allowPartialPut'] } else { 'not set' }
            }
        }
    }
    function Get-ManagerInfo([string]$Path) {
        $x = Read-Xml $Path
        if (-not $x) { return }
        foreach ($m in $x.SelectNodes('//Manager')) {
            [PSCustomObject]@{ File = $Path; Manager = $m.GetAttribute('className'); Store = ($m.SelectNodes('Store') | ForEach-Object { $_.GetAttribute('className') + ' dir=' + $_.GetAttribute('directory') }) -join '; ' }
        }
    }
    function Get-Procrun([string]$Name) {
        foreach ($root in 'HKLM:\SOFTWARE\WOW6432Node\Apache Software Foundation\Procrun 2.0', 'HKLM:\SOFTWARE\Apache Software Foundation\Procrun 2.0') {
            $p = Join-Path $root "$Name\Parameters"
            if (-not (Test-Path -LiteralPath $p)) { continue }
            $o = [ordered]@{ RegistryPath = $p }
            foreach ($k in Get-ChildItem -LiteralPath $p) {
                $props = Get-ItemProperty -LiteralPath $k.PSPath
                foreach ($n in ($props.PSObject.Properties.Name | Where-Object { $_ -notlike 'PS*' })) {
                    $v = $props.$n
                    if ($v -is [array]) { $v = $v -join ' | ' }
                    $o["$($k.PSChildName).$n"] = Hide-Secret ([string]$v)
                }
            }
            return [PSCustomObject]$o
        }
    }

    $allServices = @(Get-CimInstance Win32_Service)
    $services = @($allServices | Where-Object { $_.Name -match '(?i)tomcat' -or $_.PathName -match '(?i)tomcat' })
    $processes = @(Get-CimInstance Win32_Process | Where-Object { $_.Name -match '(?i)^(java|javaw|tomcat\d*)\.exe$' })
    $pids = @($processes | ForEach-Object ProcessId)

    $targets = @(foreach ($s in $services) {
            $procrun = Get-Procrun $s.Name
            $tcHome = $null
            if ($s.PathName -match '^"?(?<h>[^"]+?)\\bin\\[^\\]+\.exe') { $tcHome = $Matches['h'] }
            $tcBase = $tcHome
            if ($procrun -and $procrun.PSObject.Properties['Java.Options']) {
                $opt = [string]$procrun.'Java.Options'
                if ($opt -match 'catalina\.home=(?<v>[^|]+)') { $tcHome = $Matches['v'].Trim() }
                if ($opt -match 'catalina\.base=(?<v>[^|]+)') { $tcBase = $Matches['v'].Trim() }
            }
            [PSCustomObject]@{ Service = $s; Procrun = $procrun; Home = $tcHome; Base = $tcBase }
        })
    if ($Hint -and (Test-Path -LiteralPath $Hint) -and -not ($targets | Where-Object { $_.Home -and $_.Home.TrimEnd('\') -ieq $Hint.TrimEnd('\') })) {
        $targets += [PSCustomObject]@{ Service = $null; Procrun = $null; Home = $Hint.TrimEnd('\'); Base = $Hint.TrimEnd('\') }
    }

    $standardLib = '^(annotations-api|catalina(-[a-z]+)?|ecj-[\d.]+|el-api|jasper(-el)?|jaspic-api|jsp-api|servlet-api|tomcat-[a-z0-9\-]+|websocket-api|websocket-client-api)\.jar$'
    $gadgets = '(?i)commons-collections|commons-beanutils|groovy|xstream|c3p0|rome-|bsh-|jython|spring-core|hibernate-core'

    $instances = foreach ($t in ($targets | Where-Object Home)) {
        $info = Get-JarEntryText (Join-Path $t.Home 'lib\catalina.jar') 'org/apache/catalina/util/ServerInfo.properties'
        $server = Read-Xml (Join-Path $t.Base 'conf\server.xml')
        $connectors = @(); $hosts = @(); $realms = @(); $shutdownPort = $null
        if ($server) {
            $shutdownPort = $server.DocumentElement.GetAttribute('port')
            $connectors = @($server.SelectNodes('//Connector') | ForEach-Object {
                    [PSCustomObject]@{
                        Port = $_.GetAttribute('port'); Protocol = $_.GetAttribute('protocol'); Address = $_.GetAttribute('address')
                        SSLEnabled = $_.GetAttribute('SSLEnabled'); SecretRequired = $_.GetAttribute('secretRequired')
                        HasSecret = [bool]($_.GetAttribute('secret') -or $_.GetAttribute('requiredSecret'))
                        UpgradeProtocols = ($_.SelectNodes('UpgradeProtocol') | ForEach-Object { $_.GetAttribute('className') }) -join ','
                    }
                })
            $hosts = @($server.SelectNodes('//Host') | ForEach-Object {
                    [PSCustomObject]@{
                        Name = $_.GetAttribute('name'); AppBase = $_.GetAttribute('appBase'); AutoDeploy = $_.GetAttribute('autoDeploy')
                        Valves = ($_.SelectNodes('Valve') | ForEach-Object { $c = $_.GetAttribute('className'); $a = $_.GetAttribute('allow'); if ($a) { "$c allow=$a" } else { $c } }) -join '; '
                    }
                })
            $realms = @($server.SelectNodes('//Realm') | ForEach-Object { $_.GetAttribute('className') })
        }
        $appBase = Join-Path $t.Base 'webapps'
        if ($hosts -and $hosts[0].AppBase) { $appBase = if ([IO.Path]::IsPathRooted($hosts[0].AppBase)) { $hosts[0].AppBase } else { Join-Path $t.Base $hosts[0].AppBase } }
        $apps = @(Get-ChildItem -LiteralPath $appBase -Directory -ErrorAction SilentlyContinue)
        $webXmls = @(Join-Path $t.Base 'conf\web.xml') + @($apps | ForEach-Object { Join-Path $_.FullName 'WEB-INF\web.xml' })
        $contextXmls = @(Join-Path $t.Base 'conf\context.xml') +
            @(Get-ChildItem -Path (Join-Path $t.Base 'conf\Catalina') -Recurse -Filter *.xml -ErrorAction SilentlyContinue | ForEach-Object FullName) +
            @($apps | ForEach-Object { Join-Path $_.FullName 'META-INF\context.xml' })
        $users = Read-Xml (Join-Path $t.Base 'conf\tomcat-users.xml')
        $confRoot = Join-Path $t.Base 'conf'
        $jvm = if ($t.Procrun -and $t.Procrun.PSObject.Properties['Java.Jvm']) { [string]$t.Procrun.'Java.Jvm' } else { $null }

        [PSCustomObject]@{
            Home = $t.Home; Base = $t.Base
            ServerInfo = if ($info -match 'server\.info=(.+)') { $Matches[1].Trim() } else { $null }
            ServerNumber = if ($info -match 'server\.number=(\S+)') { $Matches[1].Trim() } else { $null }
            ServerBuilt = if ($info -match 'server\.built=(.+)') { $Matches[1].Trim() } else { $null }
            Service = if ($t.Service) { [PSCustomObject]@{ Name = $t.Service.Name; State = $t.Service.State; StartMode = $t.Service.StartMode; Account = $t.Service.StartName } } else { $null }
            Procrun = $t.Procrun
            Jvm = $jvm
            JvmVersion = if ($jvm -and (Test-Path -LiteralPath $jvm)) { (Get-Item -LiteralPath $jvm).VersionInfo.ProductVersion } else { $null }
            ShutdownPort = $shutdownPort; Connectors = $connectors; Hosts = $hosts; Realms = $realms
            Users = if ($users) { @($users.SelectNodes("//*[local-name()='user']") | ForEach-Object { $_.GetAttribute('username') + ': ' + $_.GetAttribute('roles') }) } else { @() }
            Servlets = @($webXmls | ForEach-Object { Get-ServletInfo $_ })
            Managers = @($contextXmls | ForEach-Object { Get-ManagerInfo $_ })
            Webapps = @(Get-ChildItem -LiteralPath $appBase -ErrorAction SilentlyContinue | ForEach-Object { $_.Name })
            GadgetLibraries = @(Get-ChildItem -Path (Join-Path $appBase '*\WEB-INF\lib\*.jar') -ErrorAction SilentlyContinue | Where-Object { $_.Name -match $gadgets } | ForEach-Object { $_.Directory.Parent.Parent.Name + '/' + $_.Name })
            ExtraLibraries = @(Get-ChildItem -LiteralPath (Join-Path $t.Home 'lib') -Filter *.jar -ErrorAction SilentlyContinue | Where-Object { $_.Name -notmatch $standardLib } | ForEach-Object Name)
            ConfHashes = @(Get-ChildItem -LiteralPath $confRoot -File -Recurse -ErrorAction SilentlyContinue | ForEach-Object {
                    [PSCustomObject]@{ Path = $_.FullName.Substring($confRoot.Length).TrimStart('\'); Hash = (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash }
                })
        }
    }

    $dns = @{}
    $resolve = { param($ip) if (-not $dns.ContainsKey($ip)) { $n = ''; try { $n = [System.Net.Dns]::GetHostEntry($ip).HostName } catch { }; $dns[$ip] = $n }; $dns[$ip] }
    $tcp = @(Get-NetTCPConnection -ErrorAction SilentlyContinue | Where-Object { $pids -contains $_.OwningProcess })
    $listen = @($tcp | Where-Object State -eq 'Listen' | Select-Object @{ n = 'Address'; e = { $_.LocalAddress } }, @{ n = 'Port'; e = { $_.LocalPort } } -Unique | Sort-Object Port)
    $listenPorts = @($listen | ForEach-Object Port)
    $established = @($tcp | Where-Object State -eq 'Established')
    $inbound = @($established | Where-Object { $listenPorts -contains $_.LocalPort } | Group-Object LocalPort, RemoteAddress | ForEach-Object {
            [PSCustomObject]@{ LocalPort = $_.Group[0].LocalPort; Remote = $_.Group[0].RemoteAddress; Host = (& $resolve $_.Group[0].RemoteAddress); Count = $_.Count }
        })
    $outbound = @($established | Where-Object { $listenPorts -notcontains $_.LocalPort } | Group-Object RemoteAddress, RemotePort | ForEach-Object {
            [PSCustomObject]@{ Remote = $_.Group[0].RemoteAddress; RemotePort = $_.Group[0].RemotePort; Host = (& $resolve $_.Group[0].RemoteAddress); Count = $_.Count }
        })
    $os = Get-CimInstance Win32_OperatingSystem
    [PSCustomObject]@{
        Computer = $env:COMPUTERNAME; Collected = (Get-Date).ToString('s'); OS = "$($os.Caption) $($os.Version)"
        JavaHome = [Environment]::GetEnvironmentVariable('JAVA_HOME', 'Machine')
        Processes = @($processes | ForEach-Object { [PSCustomObject]@{ Pid = $_.ProcessId; Name = $_.Name; CommandLine = Hide-Secret $_.CommandLine } })
        Listen = $listen; Inbound = $inbound; Outbound = $outbound
        OtherWeb = @($allServices | Where-Object { $_.Name -eq 'W3SVC' -or $_.PathName -match '(?i)httpd\.exe|nginx\.exe' } | ForEach-Object { "$($_.Name) $($_.State)" })
        Instances = @($instances)
    }
}

New-Item -ItemType Directory -Path $OutDir -Force | Out-Null
$results = @()
$targetsList = if ($Local) { @($env:COMPUTERNAME) } else { $ComputerName }
foreach ($cn in $targetsList) {
    try {
        if ($Local) { $r = & $collector $TomcatHint }
        else {
            $p = @{ ComputerName = $cn; ScriptBlock = $collector; ArgumentList = $TomcatHint; ErrorAction = 'Stop' }
            if ($Credential) { $p.Credential = $Credential }
            $r = Invoke-Command @p
        }
        $r | ConvertTo-Json -Depth 8 | Out-File -FilePath (Join-Path $OutDir (($cn -split '\.')[0] + '.json')) -Encoding UTF8
        $results += $r
        Write-Host "[OK]   $cn" -ForegroundColor Green
    }
    catch { Write-Host "[FAIL] $cn : $($_.Exception.Message)" -ForegroundColor Red }
}

$summary = foreach ($r in $results) {
    if (-not @($r.Instances).Count) { [PSCustomObject]@{ Server = $r.Computer; Home = 'Tomcat not found' }; continue }
    foreach ($i in $r.Instances) {
        $v = $i.ServerNumber
        $ajp = @($i.Connectors | Where-Object { $_.Protocol -match '(?i)ajp' })
        $http2 = @($i.Connectors | Where-Object { $_.UpgradeProtocols -match 'Http2Protocol' })
        $writable = @($i.Servlets | Where-Object { $_.ReadOnly -eq 'false' })
        $persistent = @($i.Managers | Where-Object { $_.Manager -match 'PersistentManager' })

        $ghostcat = Get-VersionState $v 'CVE-2020-1938'
        $rapidReset = Get-VersionState $v 'CVE-2023-44487'
        $partialPut = Get-VersionState $v 'CVE-2025-24813'
        [PSCustomObject]@{
            Server           = $r.Computer
            Home             = $i.Home
            Version          = "$v ($($i.ServerBuilt))"
            Service          = if ($i.Service) { "$($i.Service.Name) $($i.Service.State) $($i.Service.Account)" } else { 'no service' }
            Java             = $i.JvmVersion
            Connectors       = (@($i.Connectors) | ForEach-Object { "$($_.Port)/$($_.Protocol)$(if ($_.Address) { '@' + $_.Address })$(if ($_.SSLEnabled -eq 'true') { '/TLS' })" }) -join ', '
            Webapps          = @($i.Webapps) -join ', '
            GadgetLibraries  = @($i.GadgetLibraries) -join ', '
            'CVE-2020-1938'  = if ($ghostcat -eq 'fixed') { 'fixed by version' } elseif ($ajp) { "$($ghostcat.ToUpper()), AJP on " + (($ajp | ForEach-Object { "port $($_.Port) address $(if ($_.Address) { $_.Address } else { 'ALL' }) secret $($_.HasSecret)" }) -join '; ') } else { "$ghostcat version, AJP disabled" }
            'CVE-2023-44487' = if ($rapidReset -eq 'fixed') { 'fixed by version' } elseif ($http2) { "$($rapidReset.ToUpper()), HTTP/2 on port(s) " + (($http2 | ForEach-Object Port) -join ',') } else { "$rapidReset version, HTTP/2 disabled" }
            'CVE-2025-24813' = if ($partialPut -eq 'fixed') { 'fixed by version' } elseif ($writable) { "$($partialPut.ToUpper()), readonly=false in " + (($writable | ForEach-Object File) -join '; ') } elseif ($persistent) { "$partialPut version, readonly=true, PersistentManager present" } else { "$partialPut version, readonly=true (not exploitable in this configuration)" }
        }
    }
}
$summary = @($summary)
$summary | Export-Csv -Path (Join-Path $OutDir 'summary.csv') -NoTypeInformation -Encoding UTF8
$summary | Format-List | Out-String -Width 300 | Tee-Object -FilePath (Join-Path $OutDir 'summary.txt') | Write-Host

if ($results.Count -eq 2 -and @($results[0].Instances).Count -and @($results[1].Instances).Count) {
    $a = $results[0]; $b = $results[1]
    $ha = @{}; foreach ($h in @($a.Instances)[0].ConfHashes) { $ha[$h.Path] = $h.Hash }
    $hb = @{}; foreach ($h in @($b.Instances)[0].ConfHashes) { $hb[$h.Path] = $h.Hash }
    $compare = foreach ($k in (@($ha.Keys) + @($hb.Keys) | Sort-Object -Unique)) {
        [PSCustomObject]@{ File = $k; State = if (-not $ha.ContainsKey($k)) { "only on $($b.Computer)" } elseif (-not $hb.ContainsKey($k)) { "only on $($a.Computer)" } elseif ($ha[$k] -eq $hb[$k]) { 'same' } else { 'DIFFERENT' } }
    }
    $compare | Export-Csv -Path (Join-Path $OutDir 'conf_compare.csv') -NoTypeInformation -Encoding UTF8
    Write-Host "conf\ differences between $($a.Computer) and $($b.Computer):" -ForegroundColor Cyan
    $compare | Where-Object State -ne 'same' | Format-Table -AutoSize | Out-Host
}
Write-Host "Output: $OutDir" -ForegroundColor Cyan
$summary
