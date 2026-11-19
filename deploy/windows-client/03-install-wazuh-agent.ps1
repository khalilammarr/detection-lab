# =====================================================================
# 03 - Agent Wazuh (poste client) -> manager 10.10.10.1
# Version alignee sur le manager : 4.14.4
# A lancer dans une PowerShell ADMIN
# =====================================================================
$manager   = '10.10.10.1'
$agentName = 'CLIENT-LAB'      # nom distinct du DC
$ver       = '4.14.4'
$work      = 'C:\lab\wazuh'
New-Item -ItemType Directory -Force -Path $work | Out-Null
$msi = "$work\wazuh-agent-$ver.msi"

Invoke-WebRequest -Uri "https://packages.wazuh.com/4.x/windows/wazuh-agent-$ver-1.msi" -OutFile $msi
Start-Process msiexec.exe -Wait -ArgumentList "/i `"$msi`" /q WAZUH_MANAGER=`"$manager`" WAZUH_AGENT_NAME=`"$agentName`" WAZUH_REGISTRATION_SERVER=`"$manager`""

# Collecte du journal Sysmon
$ossec = 'C:\Program Files (x86)\ossec-agent\ossec.conf'
$block = @"
  <localfile>
    <location>Microsoft-Windows-Sysmon/Operational</location>
    <log_format>eventchannel</log_format>
  </localfile>
"@
(Get-Content $ossec -Raw) -replace '</ossec_config>', "$block`r`n</ossec_config>" | Set-Content $ossec -Encoding UTF8

Start-Service -Name WazuhSvc
Get-Service WazuhSvc | Format-List Name, Status
Write-Host "`n>>> Sur le host : agent_control -l  doit montrer CLIENT-LAB Active" -ForegroundColor Cyan
