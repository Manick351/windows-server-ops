<#
.SYNOPSIS
    Compares effective group membership and key attributes of several AD users.

.DESCRIPTION
    Answers the access-request question "give the new employee the same rights as these colleagues":

      - effective groups of every user, including nested membership and the primary group;
      - groups common to all users;
      - candidate groups that contain at least two of the users, with the number of other members
        (a group of 5 people is a better hint than "Domain Users");
      - exclusive groups that contain only users from the list;
      - comparison of Department, Title, Company, Office, employeeType, Description, OU and Manager.

    Read-only.

.PARAMETER Identity
    Users: sAMAccountName, UPN, e-mail or display name.

.PARAMETER Skip
    Group names to ignore in candidates (default: Domain Users).

.EXAMPLE
    .\Compare-ADGroupMembership.ps1 -Identity jdoe, asmith, bwhite

.EXAMPLE
    .\Compare-ADGroupMembership.ps1 -Identity jdoe, asmith | Where-Object Others -eq 0
#>
#Requires -Version 5.1
#Requires -Modules ActiveDirectory
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string[]]$Identity,

    [string[]]$Skip = @('Domain Users')
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$properties = 'DisplayName', 'mail', 'Department', 'Title', 'Company', 'Manager', 'Description', 'physicalDeliveryOfficeName', 'employeeType', 'primaryGroupID'
$matchingRule = '1.2.840.113556.1.4.1941'   # LDAP_MATCHING_RULE_IN_CHAIN: nested membership

function Get-GroupName { param([string]$Dn) (($Dn -split '(?<!\\),')[0] -replace '^CN=', '') -replace '\\(.)', '$1' }

$users = foreach ($id in ($Identity | ForEach-Object { $_.Trim() } | Where-Object { $_ } | Select-Object -Unique)) {
    $escaped = $id -replace "'", "''"
    $user = Get-ADUser -Filter "SamAccountName -eq '$escaped' -or UserPrincipalName -eq '$escaped' -or mail -eq '$escaped' -or DisplayName -eq '$escaped'" -Properties $properties |
        Select-Object -First 1
    if (-not $user) { Write-Warning "$id : not found in AD"; continue }

    $groups = @(Get-ADGroup -LDAPFilter "(member:$matchingRule`:=$($user.DistinguishedName))" | ForEach-Object DistinguishedName)
    $primarySid = $user.SID.Value -replace '-\d+$', "-$($user.primaryGroupID)"
    $primary = Get-ADGroup -Identity $primarySid -ErrorAction SilentlyContinue
    if ($primary) { $groups += $primary.DistinguishedName }
    [PSCustomObject]@{ User = $user; Groups = @($groups | Sort-Object -Unique) }
}
$users = @($users)

foreach ($u in $users) {
    Write-Host ('{0} [{1}] {2} - {3} group(s)' -f $u.User.DisplayName, $u.User.SamAccountName, $u.User.mail, $u.Groups.Count) -ForegroundColor Cyan
    $u.Groups | ForEach-Object { Get-GroupName $_ } | Sort-Object | ForEach-Object { Write-Host "    $_" }
}
if ($users.Count -lt 2) { Write-Warning 'At least two users are needed for a comparison.'; return }

$common = $users[0].Groups
foreach ($u in $users[1..($users.Count - 1)]) { $common = @($common | Where-Object { $u.Groups -contains $_ }) }
Write-Host ''
Write-Host ("COMMON TO ALL {0} USERS (nested membership included):" -f $users.Count) -ForegroundColor Green
if ($common) { $common | ForEach-Object { Get-GroupName $_ } | Sort-Object | ForEach-Object { Write-Host "    $_" -ForegroundColor Green } }
else { Write-Host '    none' -ForegroundColor Yellow }

$ourNames = @($users | ForEach-Object { $_.User.SamAccountName })
$candidates = foreach ($dn in ($users | ForEach-Object { $_.Groups } | Sort-Object -Unique)) {
    $name = Get-GroupName $dn
    if ($Skip -contains $name) { continue }
    $ours = @($users | Where-Object { $_.Groups -contains $dn })
    if ($ours.Count -lt 2) { continue }
    $members = @(Get-ADUser -LDAPFilter "(memberOf:$matchingRule`:=$dn)" | ForEach-Object SamAccountName)
    $others = @($members | Where-Object { $ourNames -notcontains $_ })
    [PSCustomObject]@{
        Group   = $name
        Ours    = $ours.Count
        Total   = $members.Count
        Others  = $others.Count
        Members = ($ours | ForEach-Object { $_.User.SamAccountName } | Sort-Object) -join ', '
        Extra   = if (-not $others) { '' } elseif ($others.Count -le 5) { ($others | Sort-Object) -join ', ' } else { "$($others.Count) users" }
    }
}
$candidates = @($candidates | Sort-Object @{ Expression = 'Ours'; Descending = $true }, Others, Group)

Write-Host ''
Write-Host 'CANDIDATE GROUPS (at least two users from the list):' -ForegroundColor Cyan
$candidates | Format-Table Group, Ours, Total, Others, Members, Extra -AutoSize -Wrap | Out-Host

Write-Host 'EXCLUSIVE GROUPS (no members outside the list):' -ForegroundColor Green
$exclusive = @($candidates | Where-Object Others -eq 0)
if ($exclusive) { foreach ($e in $exclusive) { Write-Host ('    {0} - {1} of {2} ({3})' -f $e.Group, $e.Ours, $users.Count, $e.Members) -ForegroundColor Green } }
else { Write-Host '    none' -ForegroundColor Yellow }

Write-Host ''
Write-Host 'ATTRIBUTES:' -ForegroundColor Cyan
$attributeRows = foreach ($a in 'Department', 'Title', 'Company', 'physicalDeliveryOfficeName', 'employeeType', 'Description') {
    $values = @($users | ForEach-Object { if ($_.User.$a) { [string]$_.User.$a } else { '<empty>' } } | Sort-Object -Unique)
    [PSCustomObject]@{ Attribute = $a; Same = ($values.Count -eq 1); Values = $values -join ' | ' }
}
$ous = @($users | ForEach-Object { $_.User.DistinguishedName -replace '^CN=.+?(?<!\\),', '' } | Sort-Object -Unique)
$managers = @($users | ForEach-Object { if ($_.User.Manager) { Get-GroupName $_.User.Manager } else { '<empty>' } } | Sort-Object -Unique)
$attributeRows = @($attributeRows) + [PSCustomObject]@{ Attribute = 'OU'; Same = ($ous.Count -eq 1); Values = $ous -join ' | ' } +
    [PSCustomObject]@{ Attribute = 'Manager'; Same = ($managers.Count -eq 1); Values = $managers -join ' | ' }
$attributeRows | Format-Table -AutoSize -Wrap | Out-Host

$candidates
