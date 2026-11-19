# 05-enable-pnp-audit.ps1
# Active "Audit PnP Activity" pour que le branchement d'un peripherique USB/HID
# genere l'EventID Security 6416 (base des regles Wazuh 110700-110702).
# Par defaut cet audit est DESACTIVE -> sans ce script, aucun evenement USB.
#
# On utilise le GUID de sous-categorie (independant de la langue de Windows) :
#   {0cce9248-69ae-11d9-bed3-505054503030} = Plug and Play Events
#
# A executer sur le DC (et chaque poste Windows) en administrateur :
#   iwr http://10.10.10.1:8888/05-enable-pnp-audit.ps1 -OutFile C:\Windows\Temp\05.ps1 ; powershell -ExecutionPolicy Bypass -File C:\Windows\Temp\05.ps1

$guid = "{0cce9248-69ae-11d9-bed3-505054503030}"
Write-Host "Activation de l'audit Plug and Play (6416)..."
auditpol /set /subcategory:"$guid" /success:enable /failure:enable | Out-Host

Write-Host "`nVerification :"
auditpol /get /subcategory:"$guid" | Out-Host

# Rappel : l'agent Wazuh doit deja collecter le canal Security (c'est le cas, agent 005).
# Verifier dans ossec.conf de l'agent : <localfile><location>Security</location><log_format>eventchannel</log_format>
Write-Host "`nOK. Branchez un peripherique USB pour tester -> EventID 6416 -> Wazuh 110700."
