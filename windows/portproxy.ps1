#Requires -RunAsAdministrator
<#
.SYNOPSIS
  Windows 10 fallback for distributed mode (no WSL mirrored networking):
  forwards the SOC's TCP ports from the Windows host to the WSL VM.
  The WSL IP changes on every reboot, so re-run this after each restart
  (or register it as a scheduled task at logon).

  Limitation: portproxy only forwards TCP. Syslog on 514/udp is not
  forwarded; send syslog over TCP or use mirrored networking (Windows 11).

.EXAMPLE
  .\portproxy.ps1                                  # all nodes, default distro
  .\portproxy.ps1 -Nodes core -Distro Ubuntu-24.04
  .\portproxy.ps1 -Remove
#>
param(
    [ValidateSet('core', 'cases', 'intel')]
    [string[]]$Nodes = @('core', 'cases', 'intel'),
    [string]$Distro = 'Ubuntu-24.04',
    [switch]$Remove
)
$ErrorActionPreference = 'Stop'

# TCP ports from PROJECT.md section 3.1
$Ports = @{
    core  = @(1514, 1515, 55000, 5678, 3000)
    cases = @(9000, 9001)
    intel = @(9443)
}

$wslIp = $null
if (-not $Remove) {
    $wslIp = ((wsl -d $Distro -- hostname -I) -split '\s+' | Where-Object { $_ -match '^\d+\.\d+\.\d+\.\d+$' } | Select-Object -First 1)
    if (-not $wslIp) { throw "Could not read the IP of WSL distro '$Distro'. Is it running?" }
    Write-Host "WSL IP: $wslIp"
}

foreach ($node in $Nodes) {
    foreach ($port in $Ports[$node]) {
        netsh interface portproxy delete v4tov4 listenport=$port listenaddress=0.0.0.0 2>$null | Out-Null
        if ($Remove) {
            Write-Host "REMOVED  $node tcp/$port"
            continue
        }
        netsh interface portproxy add v4tov4 listenport=$port listenaddress=0.0.0.0 connectport=$port connectaddress=$wslIp | Out-Null
        if ($LASTEXITCODE -ne 0) { Write-Host "FAIL  $node tcp/$port"; exit 1 }
        Write-Host "PASS  $node tcp/$port -> ${wslIp}:$port"
    }
}
if (-not $Remove) {
    Write-Host "Also run .\firewall-rules.ps1 to open these ports in Windows Firewall."
}
