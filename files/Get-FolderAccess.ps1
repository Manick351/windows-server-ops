<#
.SYNOPSIS
    Shows who has access to a folder (NTFS ACL) in plain terms, optionally for a whole tree.

.DESCRIPTION
    For each folder returns one row per access control entry with:
      - identity (SID translated to DOMAIN\name when possible);
      - access summarized as FullControl / Modify / Read & Execute / Read / Write / Special, including
        generic rights (GENERIC_ALL etc.) that Get-Acl shows only as numbers;
      - Allow / Deny, inherited or explicit, and what the entry applies to
        (this folder only, subfolders and files, files only, ...).

    With -Recurse the script walks the tree (up to -Depth) and reports only folders that have explicit
    (non-inherited) entries or broken inheritance - which is what an access audit usually needs.

    Read-only. Works with local and UNC paths.

.PARAMETER Path
    Folder(s) to inspect. Accepts pipeline input.

.PARAMETER Recurse
    Walk subfolders and report folders with explicit entries or disabled inheritance.

.PARAMETER Depth
    Maximum depth for -Recurse. Default: 3.

.PARAMETER ExcludeInherited
    Return only explicit entries.

.PARAMETER GridView
    Show the result in Out-GridView.

.EXAMPLE
    .\Get-FolderAccess.ps1 -Path '\\fs-01\Shares\Finance' | Format-Table Identity, Access, Type, Inherited, AppliesTo

.EXAMPLE
    .\Get-FolderAccess.ps1 -Path 'D:\Shares\Projects' -Recurse -Depth 4 | Export-Csv .\projects-acl.csv -NoTypeInformation
#>
#Requires -Version 5.1
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
    [Alias('FullName')]
    [string[]]$Path,

    [switch]$Recurse,

    [ValidateRange(1, 50)]
    [int]$Depth = 3,

    [switch]$ExcludeInherited,

    [switch]$GridView
)

begin {
    Set-StrictMode -Version Latest
    $rows = New-Object System.Collections.Generic.List[object]

    $fsr = [System.Security.AccessControl.FileSystemRights]
    function Get-AccessSummary {
        param([int64]$Mask)
        # Generic rights (high bits) appear on CREATOR OWNER and inherited-only entries.
        $genericAll = 0x10000000; $genericExecute = 0x20000000; $genericWrite = 0x40000000; $genericRead = 0x80000000
        $m = $Mask
        if ($m -band $genericAll) { return 'FullControl' }
        if ($m -band $genericRead) { $m = $m -bor [int64]$fsr::Read }
        if ($m -band $genericWrite) { $m = $m -bor [int64]$fsr::Write }
        if ($m -band $genericExecute) { $m = $m -bor [int64]$fsr::ExecuteFile }
        $m = $m -band 0x1F01FF
        $has = { param($r) ($m -band [int64]$r) -eq [int64]$r }
        if (& $has $fsr::FullControl) { return 'FullControl' }
        if (& $has $fsr::Modify) { return 'Modify' }
        $read = & $has $fsr::Read
        $readExecute = & $has $fsr::ReadAndExecute
        $write = & $has $fsr::Write
        if ($readExecute -and $write) { return 'Read & Execute + Write' }
        if ($readExecute) { return 'Read & Execute' }
        if ($read -and $write) { return 'Read + Write' }
        if ($read) { return 'Read' }
        if ($write) { return 'Write' }
        return 'Special'
    }

    function Get-AppliesTo {
        param($Rule)
        $i = $Rule.InheritanceFlags; $p = $Rule.PropagationFlags
        $container = [bool]($i -band [System.Security.AccessControl.InheritanceFlags]::ContainerInherit)
        $object = [bool]($i -band [System.Security.AccessControl.InheritanceFlags]::ObjectInherit)
        $inheritOnly = [bool]($p -band [System.Security.AccessControl.PropagationFlags]::InheritOnly)
        $noPropagate = [bool]($p -band [System.Security.AccessControl.PropagationFlags]::NoPropagateInherit)
        $text = if (-not $container -and -not $object) { 'This folder only' }
        elseif ($inheritOnly) {
            if ($container -and $object) { 'Subfolders and files only' } elseif ($container) { 'Subfolders only' } else { 'Files only' }
        }
        else {
            if ($container -and $object) { 'This folder, subfolders and files' } elseif ($container) { 'This folder and subfolders' } else { 'This folder and files' }
        }
        if ($noPropagate) { $text += ' (one level)' }
        return $text
    }

    function Get-FolderRows {
        param([string]$Folder)
        try { $acl = Get-Acl -LiteralPath $Folder -ErrorAction Stop }
        catch { Write-Warning "$Folder : $($_.Exception.Message)"; return }
        foreach ($rule in $acl.Access) {
            if ($ExcludeInherited -and $rule.IsInherited) { continue }
            $identity = $rule.IdentityReference.Value
            try { $identity = $rule.IdentityReference.Translate([System.Security.Principal.NTAccount]).Value } catch { }
            [PSCustomObject]@{
                Path                 = $Folder
                Owner                = $acl.Owner
                InheritanceProtected = $acl.AreAccessRulesProtected
                Identity             = $identity
                Access               = Get-AccessSummary ([int64]$rule.FileSystemRights)
                Type                 = "$($rule.AccessControlType)"
                Inherited            = $rule.IsInherited
                AppliesTo            = Get-AppliesTo $rule
                Rights               = "$($rule.FileSystemRights)"
            }
        }
    }
}

process {
    foreach ($p in $Path) {
        if (-not (Test-Path -LiteralPath $p -PathType Container)) { Write-Warning "Not a folder or not reachable: $p"; continue }
        $root = (Resolve-Path -LiteralPath $p).ProviderPath
        foreach ($r in (Get-FolderRows $root)) { $rows.Add($r) }
        if (-not $Recurse) { continue }

        $queue = New-Object System.Collections.Generic.Queue[object]
        $queue.Enqueue(@($root, 0))
        while ($queue.Count) {
            $item = $queue.Dequeue()
            if ($item[1] -ge $Depth) { continue }
            foreach ($sub in (Get-ChildItem -LiteralPath $item[0] -Directory -Force -ErrorAction SilentlyContinue)) {
                $queue.Enqueue(@($sub.FullName, ($item[1] + 1)))
                $subRows = @(Get-FolderRows $sub.FullName)
                if ($subRows | Where-Object { -not $_.Inherited -or $_.InheritanceProtected }) { foreach ($r in $subRows) { $rows.Add($r) } }
            }
        }
    }
}

end {
    $sorted = $rows | Sort-Object Path, @{ Expression = { $_.Type -ne 'Deny' } }, Identity
    if ($GridView) { $sorted | Out-GridView -Title 'Folder access' -PassThru } else { $sorted }
}
