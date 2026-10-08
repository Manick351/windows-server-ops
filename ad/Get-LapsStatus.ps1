<#
.SYNOPSIS
    Reports Windows LAPS / legacy LAPS password state for computer accounts and optionally e-mails the problems.

.DESCRIPTION
    For every computer the script reads the LAPS attributes in Active Directory and classifies it:

      OK        password present and not expired
      Expired   password present, expiration time in the past (the client is not rotating it)
      Missing   no LAPS password at all (no emergency local admin access)
      NotInAD   the name is not found in Active Directory

    For Expired and Missing computers it can check reachability (ICMP or real WinRM), so you get a
    short list of live machines worth investigating (for example with Compare-LapsConfiguration.ps1).

    Passwords are never read or printed: only their presence and expiration time.

    Typical uses:
      - ad-hoc audit of a list of servers;
      - monthly scheduled check of all servers in an OU with an HTML e-mail when problems exist.

.PARAMETER ComputerName
    Computer names. Accepts pipeline input (strings or objects with a Name property).

.PARAMETER ListPath
    Text file with one computer name per line (# comments allowed).

.PARAMETER SearchBase
    Distinguished name of an OU. All enabled computers with a server OS under it are checked.

.PARAMETER Reachability
    How to check problem computers: None, Ping or WinRM (default, includes ping).

.PARAMETER IncludeExpired
    Treat expired passwords as problems. Default: $true.

.PARAMETER OutputPath
    Folder for the CSV report and the lists of reachable / unreachable problem computers.

.PARAMETER SmtpServer
    Send an HTML report through this SMTP server when problems are found.

.PARAMETER From
    Sender address for the report.

.PARAMETER To
    Recipients for the report.

.PARAMETER MailCredential
    Credential for the SMTP server (for example from Get-Secret or Import-Clixml).

.PARAMETER Port
    SMTP port. Default: 587.

.PARAMETER UseSsl
    Use STARTTLS / SSL for SMTP.

.EXAMPLE
    .\Get-LapsStatus.ps1 -ListPath .\servers.txt | Format-Table

.EXAMPLE
    .\Get-LapsStatus.ps1 -SearchBase 'OU=Servers,DC=contoso,DC=local' -Reachability None -OutputPath C:\Reports\LAPS

.EXAMPLE
    .\Get-LapsStatus.ps1 -SearchBase 'OU=Servers,DC=contoso,DC=local' -SmtpServer smtp.contoso.local -UseSsl `
        -From laps-report@contoso.local -To it-ops@contoso.local -MailCredential (Import-Clixml C:\Secure\smtp.xml)

.NOTES
    Requires the ActiveDirectory module (RSAT). Reading msLAPS-* attributes may require delegated rights;
    without them a present password can look "Missing" - run with an account that can read LAPS metadata.
#>
#Requires -Version 5.1
#Requires -Modules ActiveDirectory
[CmdletBinding(DefaultParameterSetName = 'ByName')]
param(
    [Parameter(ParameterSetName = 'ByName', Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
    [Alias('Name')]
    [string[]]$ComputerName,

    [Parameter(ParameterSetName = 'ByList', Mandatory = $true)]
    [string]$ListPath,

    [Parameter(ParameterSetName = 'ByOU', Mandatory = $true)]
    [string]$SearchBase,

    [ValidateSet('None', 'Ping', 'WinRM')]
    [string]$Reachability = 'WinRM',

    [bool]$IncludeExpired = $true,

    [string]$OutputPath,

    [string]$SmtpServer,
    [string]$From,
    [string[]]$To,
    [pscredential]$MailCredential,
    [int]$Port = 587,
    [switch]$UseSsl
)

begin {
    Set-StrictMode -Version Latest
    $ErrorActionPreference = 'Stop'
    $names = New-Object System.Collections.Generic.List[string]
    $properties = 'OperatingSystem', 'msLAPS-Password', 'msLAPS-EncryptedPassword', 'msLAPS-PasswordExpirationTime',
        'ms-Mcs-AdmPwd', 'ms-Mcs-AdmPwdExpirationTime'

    function Test-Reachable {
        param([string]$Name)
        switch ($Reachability) {
            'None' { return $null }
            'Ping' { return [bool](Test-Connection -ComputerName $Name -Count 1 -Quiet -ErrorAction SilentlyContinue) }
            'WinRM' {
                if (-not (Test-Connection -ComputerName $Name -Count 1 -Quiet -ErrorAction SilentlyContinue)) { return $false }
                try { [void](Test-WSMan -ComputerName $Name -ErrorAction Stop); return $true } catch { return $false }
            }
        }
    }

    function Get-Attribute {
        param($Object, [string]$Name)
        if ($Object.PSObject.Properties[$Name]) { return $Object.$Name }
        return $null
    }
}

process {
    if ($PSCmdlet.ParameterSetName -eq 'ByName') {
        foreach ($n in $ComputerName) { if ($n) { $names.Add(($n.Trim() -split '\.')[0]) } }
    }
}

end {
    if ($PSCmdlet.ParameterSetName -eq 'ByList') {
        Get-Content -LiteralPath $ListPath | ForEach-Object { $_.Trim() } |
            Where-Object { $_ -and $_ -notmatch '^#' } | ForEach-Object { $names.Add(($_ -split '\.')[0]) }
    }
    if ($PSCmdlet.ParameterSetName -eq 'ByOU') {
        Get-ADComputer -SearchBase $SearchBase -Filter 'Enabled -eq $true -and OperatingSystem -like "*Server*"' |
            ForEach-Object { $names.Add($_.Name) }
    }
    $unique = @($names | Sort-Object -Unique)
    Write-Verbose "Computers to check: $($unique.Count)"

    $now = Get-Date
    $results = foreach ($name in $unique) {
        $row = [ordered]@{ Name = $name; Status = 'NotInAD'; LapsType = ''; Expiration = $null; OperatingSystem = ''; Reachable = $null }
        try { $computer = Get-ADComputer -Identity $name -Properties $properties }
        catch { [PSCustomObject]$row; continue }

        $row.OperatingSystem = $computer.OperatingSystem
        $windowsLaps = [bool]((Get-Attribute $computer 'msLAPS-Password') -or (Get-Attribute $computer 'msLAPS-EncryptedPassword'))
        $legacyLaps = [bool](Get-Attribute $computer 'ms-Mcs-AdmPwd')
        $expiryRaw = Get-Attribute $computer 'msLAPS-PasswordExpirationTime'
        if (-not $expiryRaw) { $expiryRaw = Get-Attribute $computer 'ms-Mcs-AdmPwdExpirationTime' }

        $row.LapsType = if ($windowsLaps) { 'Windows LAPS' } elseif ($legacyLaps) { 'Legacy LAPS' } elseif ($expiryRaw) { 'Unknown (no read access?)' } else { '' }
        if ($expiryRaw) { $row.Expiration = [datetime]::FromFileTime([int64]$expiryRaw) }

        $present = $windowsLaps -or $legacyLaps -or [bool]$expiryRaw
        $row.Status = if (-not $present) { 'Missing' } elseif ($row.Expiration -and $row.Expiration -lt $now) { 'Expired' } else { 'OK' }

        $isProblem = $row.Status -eq 'Missing' -or ($IncludeExpired -and $row.Status -eq 'Expired')
        if ($isProblem) { $row.Reachable = Test-Reachable $name }
        [PSCustomObject]$row
    }
    $results = @($results)

    $summary = $results | Group-Object Status | ForEach-Object { '{0}={1}' -f $_.Name, $_.Count }
    Write-Host ('LAPS status: {0} computer(s): {1}' -f $results.Count, ($summary -join ', ')) -ForegroundColor Cyan

    $problems = @($results | Where-Object { $_.Status -eq 'Missing' -or $_.Status -eq 'NotInAD' -or ($IncludeExpired -and $_.Status -eq 'Expired') })

    if ($OutputPath) {
        if (-not (Test-Path -LiteralPath $OutputPath)) { New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null }
        $stamp = Get-Date -Format 'yyyyMMdd_HHmm'
        $results | Export-Csv -LiteralPath (Join-Path $OutputPath "LAPS_status_$stamp.csv") -NoTypeInformation -Encoding UTF8
        $problems | Where-Object { $_.Reachable -eq $true } | ForEach-Object Name |
            Set-Content -LiteralPath (Join-Path $OutputPath 'LAPS_problem_reachable.txt') -Encoding UTF8
        $problems | Where-Object { $_.Reachable -eq $false } | ForEach-Object Name |
            Set-Content -LiteralPath (Join-Path $OutputPath "LAPS_problem_unreachable_$stamp.txt") -Encoding UTF8
        Write-Host "Reports saved to $OutputPath" -ForegroundColor Green
    }

    if ($SmtpServer -and $problems) {
        if (-not $From -or -not $To) { throw 'Use -From and -To together with -SmtpServer.' }
        $section = {
            param($Title, $Items, $Color)
            if (-not $Items) { return '' }
            $rows = ($Items | ForEach-Object { "<tr><td style='padding:3px 10px;border:1px solid #ccc'>$([System.Net.WebUtility]::HtmlEncode($_))</td></tr>" }) -join ''
            "<h3 style='color:$Color'>$Title ($(@($Items).Count))</h3><table style='border-collapse:collapse'>$rows</table>"
        }
        $missing = @($problems | Where-Object Status -eq 'Missing' | ForEach-Object Name)
        $expired = @($problems | Where-Object Status -eq 'Expired' | ForEach-Object { '{0} - expired {1:yyyy-MM-dd}' -f $_.Name, $_.Expiration })
        $notInAd = @($problems | Where-Object Status -eq 'NotInAD' | ForEach-Object Name)
        $body = "<p>LAPS check of $($results.Count) computer(s), $(Get-Date -Format 'yyyy-MM-dd HH:mm').</p>" +
            "<p>$($summary -join ' | ')</p>" +
            (& $section 'No LAPS password (no emergency local access)' $missing '#C00000') +
            (& $section 'LAPS password expired (client not rotating)' $expired '#B8860B') +
            (& $section 'Not found in Active Directory' $notInAd '#666666')
        $mail = @{
            SmtpServer = $SmtpServer; Port = $Port; From = $From; To = $To; BodyAsHtml = $true; Encoding = [Text.Encoding]::UTF8
            Subject    = "LAPS: problems on $($problems.Count) computer(s) ($(Get-Date -Format 'yyyy-MM-dd'))"
            Body       = $body
        }
        if ($UseSsl) { $mail.UseSsl = $true }
        if ($MailCredential) { $mail.Credential = $MailCredential }
        Send-MailMessage @mail
        Write-Host "Report sent to $($To -join ', ')" -ForegroundColor Green
    }

    $results
}
