# =====================================================================
# 01 - Jonction du poste client au domaine lab.local
# VM : CLIENT-LAB (Windows 10/11)
# Prealable : le DC (10.10.10.10) est promu et joignable.
# A lancer dans une PowerShell ADMIN sur le POSTE CLIENT
# =====================================================================

# --- 0. Reseau : le client DOIT utiliser le DC comme DNS --------------
$ifAlias = (Get-NetAdapter | Where-Object {$_.Status -eq 'Up'} | Select-Object -First 1).Name
$dcIp    = '10.10.10.10'        # DNS = le contrôleur de domaine

# IP fixe (recommande) ou laisse le DHCP host-only. Ici IP fixe :
New-NetIPAddress -InterfaceAlias $ifAlias -IPAddress '10.10.10.20' -PrefixLength 24 -DefaultGateway '10.10.10.1' -ErrorAction SilentlyContinue
Set-DnsClientServerAddress -InterfaceAlias $ifAlias -ServerAddresses $dcIp

# --- 1. Verif que le DC repond ----------------------------------------
Write-Host "[*] Test resolution du domaine..." -ForegroundColor Cyan
Resolve-DnsName 'lab.local' -ErrorAction Stop | Select-Object Name, IPAddress

# --- 2. Nom de machine lisible (optionnel) ----------------------------
Rename-Computer -NewName 'PC-SOUSCRIPTION01' -Force -ErrorAction SilentlyContinue

# --- 3. Jonction au domaine -------------------------------------------
#   Identifiants d'un compte autorise a joindre (ex. Administrateur du domaine).
$cred = Get-Credential -Message "Compte du domaine LAB (ex. LAB\Administrateur)"
Add-Computer -DomainName 'lab.local' -Credential $cred -Restart -Force

# Le poste redemarre et rejoint le domaine.
# Apres reboot : se connecter avec un compte du domaine, ex. LAB\user2
