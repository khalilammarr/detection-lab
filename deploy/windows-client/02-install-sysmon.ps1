# =====================================================================
# 02 - Sysmon sur le poste client (memes reglages que le DC)
# A lancer dans une PowerShell ADMIN, apres jonction au domaine
# =====================================================================
$work = 'C:\lab\sysmon'
New-Item -ItemType Directory -Force -Path $work | Out-Null
Set-Location $work

Invoke-WebRequest -Uri 'https://download.sysinternals.com/files/Sysmon.zip' -OutFile "$work\Sysmon.zip"
Expand-Archive -Path "$work\Sysmon.zip" -DestinationPath $work -Force
Invoke-WebRequest -Uri 'https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml' -OutFile "$work\sysmonconfig.xml"

& "$work\Sysmon64.exe" -accepteula -i "$work\sysmonconfig.xml"
Get-WinEvent -ListLog 'Microsoft-Windows-Sysmon/Operational' | Format-List LogName, RecordCount
