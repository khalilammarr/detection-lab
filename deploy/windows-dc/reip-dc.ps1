# Re-IP the DC from 10.10.10.10 (vboxnet0) to 10.10.20.10 (protected LAN behind OPNsense)
# Keeps NAT NIC default route for internet; adds explicit route to the Wazuh manager subnet via OPNsense LAN gw.
$ErrorActionPreference = 'SilentlyContinue'

$ifAlias = (Get-NetIPAddress -IPAddress 10.10.10.10 -AddressFamily IPv4).InterfaceAlias
if (-not $ifAlias) {
    # fallback: the adapter that is NOT the NAT 10.0.x one
    $ifAlias = (Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.IPAddress -like '192.168.*' } | Select-Object -First 1).InterfaceAlias
}
if (-not $ifAlias) {
    "ERROR: could not find protected interface" | Out-File C:\reip-done.txt
    return
}

# 1) add new IP on the protected segment
New-NetIPAddress -InterfaceAlias $ifAlias -IPAddress 10.10.20.10 -PrefixLength 24 -ErrorAction SilentlyContinue | Out-Null

# 2) remove the old vboxnet0 IP
Remove-NetIPAddress -IPAddress 10.10.10.10 -Confirm:$false -ErrorAction SilentlyContinue

# 3) DNS -> self on new address (DC is its own DNS)
Set-DnsClientServerAddress -InterfaceAlias $ifAlias -ServerAddresses 10.10.20.10 -ErrorAction SilentlyContinue

# 4) explicit route to the Wazuh manager subnet (10.10.10.0/24) via the OPNsense LAN gateway
Remove-NetRoute -DestinationPrefix '10.10.10.0/24' -Confirm:$false -ErrorAction SilentlyContinue
New-NetRoute -DestinationPrefix '10.10.10.0/24' -InterfaceAlias $ifAlias -NextHop 10.10.20.1 -Confirm:$false -ErrorAction SilentlyContinue | Out-Null

# 5) restart the Wazuh agent so it re-establishes its manager connection promptly
Restart-Service -Name WazuhSvc -ErrorAction SilentlyContinue

"DONE reip iface=$ifAlias -> 10.10.20.10/24 route56via57.1 $(Get-Date)" | Out-File C:\reip-done.txt
