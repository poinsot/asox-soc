#Requires -RunAsAdministrator
<#
.SYNOPSIS
  Opens the SOC's published ports in Windows Firewall (and, with WSL mirrored
  networking, in the Hyper-V firewall). Only needed in distributed mode.

.EXAMPLE
  .\firewall-rules.ps1                       # all nodes
  .\firewall-rules.ps1 -Nodes core,cases     # only the nodes this machine runs
  .\firewall-rules.ps1 -Remove               # delete the rules again
#>
param(
    [ValidateSet('core', 'cases', 'intel')]
    [string[]]$Nodes = @('core', 'cases', 'intel'),
    [switch]$Remove
)
$ErrorActionPreference = 'Stop'

# PROJECT.md section 3.1
$Ports = @{
    core  = @(@{P='TCP'; N='1514,1515,55000,5678,3000'}, @{P='UDP'; N='514'})
    cases = @(@{P='TCP'; N='9000,9001'})
    intel = @(@{P='TCP'; N='9443'})
}
# VM creator ID of WSL, used by the Hyper-V firewall (mirrored networking).
$WslVmCreatorId = '{40E0AC32-46A5-438A-A0B2-2B479E8F2E90}'
$HaveHyperVFirewall = [bool](Get-Command New-NetFirewallHyperVRule -ErrorAction SilentlyContinue)

foreach ($node in $Nodes) {
    foreach ($rule in $Ports[$node]) {
        $name = "ASOX SOC $node $($rule.P)"
        $ports = $rule.N -split ','
        Get-NetFirewallRule -DisplayName $name -ErrorAction SilentlyContinue | Remove-NetFirewallRule
        if ($HaveHyperVFirewall) {
            Get-NetFirewallHyperVRule -Name "asox-soc-$node-$($rule.P)" -ErrorAction SilentlyContinue | Remove-NetFirewallHyperVRule
        }
        if ($Remove) {
            Write-Host "REMOVED  $name"
            continue
        }
        New-NetFirewallRule -DisplayName $name -Direction Inbound -Action Allow `
            -Protocol $rule.P -LocalPort $ports -Profile Domain,Private | Out-Null
        Write-Host "PASS  Windows Firewall: $name ($($rule.N))"
        if ($HaveHyperVFirewall) {
            New-NetFirewallHyperVRule -Name "asox-soc-$node-$($rule.P)" -DisplayName $name `
                -Direction Inbound -Action Allow -VMCreatorId $WslVmCreatorId `
                -Protocol $rule.P -LocalPorts $ports | Out-Null
            Write-Host "PASS  Hyper-V firewall: $name ($($rule.N))"
        }
    }
}
if (-not $HaveHyperVFirewall -and -not $Remove) {
    Write-Host "SKIP  Hyper-V firewall cmdlets not available (Windows 10 or older WSL); not needed with portproxy"
}
