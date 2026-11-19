# =====================================================================
# 02 - Sysmon (journalisation fine : process, reseau, DLL, etc.)
# Config de reference : SwiftOnSecurity (tres utilisee en SOC)
# A lancer dans une PowerShell ADMIN
# =====================================================================

$work = 'C:\lab\sysmon'
New-Item -ItemType Directory -Force -Path $work | Out-Null
Set-Location $work

# --- Telechargement Sysmon (Sysinternals) -------------------------------
Invoke-WebRequest -Uri 'https://download.sysinternals.com/files/Sysmon.zip' -OutFile "$work\Sysmon.zip"
Expand-Archive -Path "$work\Sysmon.zip" -DestinationPath $work -Force

# --- Config SwiftOnSecurity --------------------------------------------
Invoke-WebRequest -Uri 'https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml' -OutFile "$work\sysmonconfig.xml"

# --- Installation ------------------------------------------------------
& "$work\Sysmon64.exe" -accepteula -i "$work\sysmonconfig.xml"

# Verif : le journal doit exister
Get-WinEvent -ListLog 'Microsoft-Windows-Sysmon/Operational' | Format-List LogName, RecordCount
