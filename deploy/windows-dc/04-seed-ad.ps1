# =====================================================================
# 04 - Peuplement AD "SOC Lab" : OU + utilisateurs de test
# Donne du realisme + des cibles pour les attaques (brute-force, kerberoast...)
# A lancer sur le DC apres promotion, PowerShell ADMIN
# =====================================================================

Import-Module ActiveDirectory
$dn = 'DC=lab,DC=local'

# --- OU metier ----------------------------------------------------------
foreach ($ou in 'Direction','Souscription','Sinistres','IT','Comptabilite') {
    New-ADOrganizationalUnit -Name $ou -Path $dn -ProtectedFromAccidentalDeletion $false -ErrorAction SilentlyContinue
}

# --- Utilisateurs de test (mot de passe LAB uniquement) -----------------
# Lab password: never hardcoded. Set LAB_PASSWORD in the session before running:
#   $env:LAB_PASSWORD = Read-Host 'Lab password'
if (-not $env:LAB_PASSWORD) { throw 'Set $env:LAB_PASSWORD first' }
$pwd = ConvertTo-SecureString $env:LAB_PASSWORD -AsPlainText -Force
$users = @(
    @{N='User One';    S='user1';  OU='Direction'},
    @{N='User Two';     S='user2';  OU='Souscription'},
    @{N='User Three';    S='user3';  OU='Sinistres'},
    @{N='Admin IT';         S='adminit';  OU='IT'},
    @{N='Compta Paie';      S='cpaie';    OU='Comptabilite'}
)
foreach ($u in $users) {
    New-ADUser -Name $u.N -SamAccountName $u.S `
        -UserPrincipalName "$($u.S)@lab.local" `
        -Path "OU=$($u.OU),$dn" `
        -AccountPassword $pwd -Enabled $true `
        -ChangePasswordAtLogon $false -ErrorAction SilentlyContinue
}

# --- Un compte "service" volontairement kerberoastable (SPN) ------------
New-ADUser -Name 'svc-sql' -SamAccountName 'svc-sql' `
    -UserPrincipalName 'svc-sql@lab.local' `
    -Path "OU=IT,$dn" -AccountPassword $pwd -Enabled $true -ErrorAction SilentlyContinue
Set-ADUser -Identity 'svc-sql' -ServicePrincipalNames @{Add='MSSQLSvc/db01.lab.local:1433'}

Get-ADUser -Filter * | Select-Object Name, SamAccountName | Format-Table -AutoSize
