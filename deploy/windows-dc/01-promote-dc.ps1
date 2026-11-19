# =====================================================================
# 01 - Promotion du serveur en Contrôleur de Domaine (AD DS + DNS)
# Domaine : lab.local   |   NetBIOS : LAB
# A lancer dans une PowerShell ADMIN sur la VM DC-LAB
# =====================================================================

# --- 0. (Recommande) IP statique sur l interface reseau host-only ------------------
#   Adapte l'index d'interface (Get-NetAdapter) si besoin.
#   Le DC DOIT avoir une IP fixe et se pointer lui-meme en DNS.
# Set $env:LAB_PASSWORD (directory-services restore mode password) before running.
if (-not $env:LAB_PASSWORD) { throw 'Set $env:LAB_PASSWORD first' }

$ifAlias   = (Get-NetAdapter | Where-Object {$_.Status -eq 'Up'} | Select-Object -First 1).Name
$dcIp      = '10.10.10.10'      # IP fixe du DC sur le segment host-only
$prefix    = 24
$gateway   = '10.10.10.1'       # host Arch (passerelle du segment)

New-NetIPAddress   -InterfaceAlias $ifAlias -IPAddress $dcIp -PrefixLength $prefix -DefaultGateway $gateway -ErrorAction SilentlyContinue
Set-DnsClientServerAddress -InterfaceAlias $ifAlias -ServerAddresses '127.0.0.1'

# --- 1. Nom de machine lisible (optionnel) ------------------------------
Rename-Computer -NewName 'DC01' -Force -ErrorAction SilentlyContinue

# --- 2. Installation du role AD DS --------------------------------------
Install-WindowsFeature -Name AD-Domain-Services -IncludeManagementTools

# --- 3. Creation de la foret / promotion --------------------------------
# Splatting (hashtable) au lieu des backticks : robuste aux sauts de ligne / espaces residuels
Import-Module ADDSDeployment
$adds = @{
    DomainName                    = 'lab.local'
    DomainNetbiosName             = 'LAB'
    ForestMode                    = 'WinThreshold'
    DomainMode                    = 'WinThreshold'
    InstallDns                    = $true
    CreateDnsDelegation           = $false
    DatabasePath                  = 'C:\Windows\NTDS'
    LogPath                       = 'C:\Windows\NTDS'
    SysvolPath                    = 'C:\Windows\SYSVOL'
    NoRebootOnCompletion          = $false
    Force                         = $true
    SafeModeAdministratorPassword = (ConvertTo-SecureString $env:LAB_PASSWORD -AsPlainText -Force)
}
Install-ADDSForest @adds

# Le serveur redemarre automatiquement. Apres reboot -> il est DC.
