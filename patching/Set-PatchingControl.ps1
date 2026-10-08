<#
.SYNOPSIS
    Sends a control command to servers in a running Invoke-ServerPatching.ps1 run.

.DESCRIPTION
    Workers check <WorkFolder>\control\<server>.txt between steps:

      Stop    abort the server's job after the current step (an installation already running on the
              server is not interrupted, but no reboot or further rounds follow);
      Reboot  approve a reboot for a server waiting in RebootMode Manual.

.PARAMETER WorkFolder
    Work folder of the run.

.PARAMETER ComputerName
    Servers to send the command to.

.PARAMETER All
    Send the command to every server of the run that has not finished.

.PARAMETER Action
    Stop or Reboot.

.EXAMPLE
    .\Set-PatchingControl.ps1 -WorkFolder .\PatchRun_20261008_1800 -ComputerName srv-db-01 -Action Reboot

.EXAMPLE
    .\Set-PatchingControl.ps1 -WorkFolder .\PatchRun_20261008_1800 -All -Action Stop
#>
#Requires -Version 5.1
[CmdletBinding(SupportsShouldProcess = $true, DefaultParameterSetName = 'ByName')]
param(
    [Parameter(Mandatory = $true)][string]$WorkFolder,
    [Parameter(Mandatory = $true, ParameterSetName = 'ByName')][string[]]$ComputerName,
    [Parameter(Mandatory = $true, ParameterSetName = 'All')][switch]$All,
    [Parameter(Mandatory = $true)][ValidateSet('Stop', 'Reboot')][string]$Action
)

Set-StrictMode -Version Latest
$controlDir = Join-Path $WorkFolder 'control'
$statusDir = Join-Path $WorkFolder 'status'
if (-not (Test-Path -LiteralPath $controlDir)) { throw "Not a patching work folder: $WorkFolder" }

$targets = if ($All) {
    Get-ChildItem -LiteralPath $statusDir -Filter *.json | ForEach-Object {
        $s = Get-Content -LiteralPath $_.FullName -Raw | ConvertFrom-Json
        if (-not $s.Result) { $s.Server }
    }
}
else { $ComputerName | ForEach-Object { $_.Trim().ToLower() } }

foreach ($t in $targets) {
    if (-not (Test-Path -LiteralPath (Join-Path $statusDir "$t.json"))) { Write-Warning "$t is not part of this run"; continue }
    if ($PSCmdlet.ShouldProcess($t, $Action)) {
        Set-Content -LiteralPath (Join-Path $controlDir "$t.txt") -Value $Action -Encoding ASCII
        Write-Host "$Action sent to $t (picked up within ~15 seconds)" -ForegroundColor Green
    }
}
