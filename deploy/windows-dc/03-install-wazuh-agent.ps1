# =====================================================================
# 03 - Agent Wazuh (Windows) -> manager 10.10.10.1
# Version alignee sur le manager : 4.14.4
# A lancer dans une PowerShell ADMIN
# =====================================================================

$manager   = '10.10.10.1'          # host Arch ou tourne Wazuh
$agentName = 'DC-LAB'
$ver       = '4.14.4'
$work      = 'C:\lab\wazuh'
New-Item -ItemType Directory -Force -Path $work | Out-Null
$msi = "$work\wazuh-agent-$ver.msi"

# --- Telechargement MSI -------------------------------------------------
Invoke-WebRequest -Uri "https://packages.wazuh.com/4.x/windows/wazuh-agent-$ver-1.msi" -OutFile $msi

# --- Installation + enrol/inscription automatique -----------------------
Start-Process msiexec.exe -Wait -ArgumentList "/i `"$msi`" /q WAZUH_MANAGER=`"$manager`" WAZUH_AGENT_NAME=`"$agentName`" WAZUH_REGISTRATION_SERVER=`"$manager`""

# --- Ajout de la collecte du journal Sysmon dans ossec.conf -------------
$ossec = 'C:\Program Files (x86)\ossec-agent\ossec.conf'
$block = @"
  <localfile>
    <location>Microsoft-Windows-Sysmon/Operational</location>
    <log_format>eventchannel</log_format>
  </localfile>
"@
# insere juste avant </ossec_config>
(Get-Content $ossec -Raw) -replace '</ossec_config>', "$block`r`n</ossec_config>" | Set-Content $ossec -Encoding UTF8

# --- Demarrage du service ----------------------------------------------
Start-Service -Name WazuhSvc
Get-Service WazuhSvc | Format-List Name, Status

Write-Host "`n>>> Sur le host, verifie l'agent :  docker exec -it <wazuh-manager> /var/ossec/bin/agent_control -l" -ForegroundColor Cyan
