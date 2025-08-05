clear
date
Write-Host "Script version 1.1" -ForegroundColor Cyan
Write-Host "https://github.com/evs-zdl/public" -ForegroundColor Cyan
# you'll probably want FullLanguage mode rather than Constrained before running this as well as an AMSI bypass.
# so you'll want a ConstrainedLanguage mode and AMSI bypass.
# import powerview and active directory dll into your session then run the below

if(!($ExecutionContext.SessionState.LanguageMode -eq "FullLanguage")){
    Write-Host "WARNING: You're not in FullLanguage mode. Things will not work." -ForegroundColor Red
}else{
    Write-Host "You're in FullLanguage mode. Good." -ForegroundColor Green
}
if (!(Get-Command Get-DomainUser -errorAction SilentlyContinue))
{
    Write-Host "PowerView doesn't seem to be imported. Please load this first e.g. Copy and paste it into your PS console" -ForegroundColor red
}else{
    Write-Host "PowerView already imported." -ForegroundColor Green
}
if (!(Get-Command Get-ADUser -errorAction SilentlyContinue))
{
    Write-Host "AD module/DLL doesn't seem to be imported. Please load this first e.g. Import-Module <Full_DLL_Path>.dll" -ForegroundColor red
}else{
    Write-Host "AD module/DLL already imported." -ForegroundColor Green
}

Write-Host ""
Write-Host "If you can't run this, you'll have to refer to an alternative like powerview.py, but you'll want to script something equivalent for that."  -foregroundcolor yellow
Write-Host "This will output CSV files to your current working directory, just an FYI."  -foregroundcolor yellow

Write-Host "###################################################################################"  -foregroundcolor yellow
Write-Host "Change directory to somewhere where you want the results to be written to first..."  -foregroundcolor Cyan
Write-Host "###################################################################################"  -foregroundcolor yellow

Write-Host ""
Write-Host "Just a heads up, this is a rudimentary script (put together for an assessment), which essentially just sequentially runs separate cmdlets/commands for each possible AD finding type. Please feel free to let me know / update this script if you know of more."
Write-Host "Possible to-do:"
Write-Host "- Use runspaces and/or jobs for multitasking (probably poor opsec)"
Write-Host "- Don't output to CSV if CSV would be empty (currently searches for and clears empty CSV files in current working directory at script conclusion)"
Write-Host "- A N Other"

Write-Host ""
Read-Host "Press Return to continue or CTRL+C to cancel"
Write-Host ""
Write-Host "Dynamically retrieving the list of domain suffixes configured on the local machine. These suffixes are used to search for AD domains." -Foregroundcolor Yellow
$domains = (Get-DnsClientGlobalSetting).SuffixSearchList # populate dynamically from DNS suffix search

$daysago = (Get-Date).AddDays(-90).ToFileTime()

$ErrorActionPreference = "SilentlyContinue"

foreach($domain in $domains){

write-host "===========================================================" -ForegroundColor Cyan
write-host "===========================================================" -ForegroundColor Cyan
# Test Accounts Present in AD
Write-Host "Domain: $($domain)" -ForegroundColor Yellow
Write-Host "Test Accounts Present in Active Directory"  
Get-DomainUser -Domain $domain -UACFilter NOT_ACCOUNTDISABLE -ErrorAction SilentlyContinue | where {$_.Name -like "*test*" -or $_.Name -like "*temp*"} | select name, userprincipalname | Export-CSV Enabled_Test_or_Temp_Accounts_$domain.csv -NoTypeInformation -Append  
write-host ""

<#
# Get delegated admin accounts which are enabled (Administrators Allowed For Delegation)
Write-Host "Get delegated admin accounts which are enabled..." -ForegroundColor Yellow
Get-DomainUser -AdminCount -Domain $domain | Where-Object {  $_.UserAccountControl -notmatch 'NOT_DELEGATED' -and $_.UserAccountControl -notmatch 'ACCOUNTDISABLE' } | Select-Object samaccountname, memberof | Export-CSV Enabled_Delegated_Admin_Accounts_$domain.csv -NoTypeInformation -Append 
write-host ""
#>

Write-Host "Insufficient KRBTTGT Password Rotation"
# Define a function to check the last password change of the krbtgt account
function Get-KrbtgtLastChange {
    # Retrieve the krbtgt account details
    $krbtgtAccount = Get-DomainUser -Identity "krbtgt" -Properties pwdLastSet -Domain $domain

    # Check if the pwdLastSet property exists
    if ($krbtgtAccount.pwdLastSet) {
        # Check if the password was changed more than 180 days ago
        if ($krbtgtAccount.pwdLastSet -lt (Get-Date).AddDays(-180)) {
            Write-Output "krbtgt password is out of date. Last changed on $($krbtgtAccount.pwdLastSet)."

$($krbtgtAccount.pwdlastset) | Export-Csv -NoTypeInformation -Append krbtgt_pwd_last_set_greater_than_6_months_ago_$domain.csv
        } else {
            Write-Output "krbtgt password is up to date. Last changed on $($krbtgtAccount.pwdLastSet)."
        }  
    } else {
        Write-Output "[!] Could not retrieve pwdLastSet for krbtgt account."
    }
}

Get-KrbtgtLastChange

# machine quota above 0
$domainParts = $domain -split '\.'
$distinguishedName = ($domainParts | ForEach-Object { "DC=$_" }) -join ','
Get-DomainObject -DistinguishedName "$distinguishedName" -ErrorAction SilentlyContinue | Select-Object ms-ds-machineaccountquota | Export-Csv -NoTypeInformation -Append machine_quota_above_0_$domain.csv

# Get Kerberoastable users
Write-Host "Kerberoastable users:"
Invoke-Kerberoast -Domain $domain -OutputFormat Hashcat -ErrorAction SilentlyContinue | Select-Object -ExpandProperty hash  | Out-File kerberoastable_hashes_$domain.out -Append -Encoding ASCII 
Write-Host "If you found some, go and use impacket-GetNPUsers and/or Rubeus to get as-rep roasting hashes with hashcat mode 18200."
Write-Host ""

# Get AS-Rep Roastable users
Write-Host "AS-REP Roastable users:"
Get-DomainUser -PreauthNotRequired -Domain $domain -ErrorAction SilentlyContinue | Out-File as_rep_roastable_users_$domain.out -Append
write-host ""

# Admins allowed for delegation
Write-Host "Admins allowed for delegation:"
Get-DomainUser -AdminCount -Domain $domain -ErrorAction SilentlyContinue | Where-Object { $_.UserAccountControl -notmatch "NOT_DELEGATED" -and $_.UserAccountControl -notmatch "ACCOUNTDISABLE" } | Select-Object samaccountname, {Name='memberof';Expression={$_.memberof -join ', '}} | Export-Csv -NoTypeInformation -Append admins_allowed_for_delegation_$domain.csv
write-host ""

# Users with SID History Enabled
Write-Host "Getting users with SID History Enabled"
get-DomainUser -Domain $domain -LDAPFilter '(SIDHistory=*)' | select UserPrincipalName | Export-CSV Users_With_SID_History_Enabled_$domain.csv -NoTypeInformation -Append
write-host ""

Write-Host "Enabled accounts with old passwords"  
Get-DomainUser -LDAPFilter "(pwdlastset<=$daysago)" -Properties * -Domain $domain -ErrorAction SilentlyContinue | ? {$_.UserAccountControl -notlike "*ACCOUNTDISABLE*"} | select userprincipalname,pwdlastset | Export-Csv -NoTypeInformation -Append enabled_accounts_pwds_not_changed_over_90_days_$domain.csv
write-host ""

<#
# get DCs not owned by Domain Admins
write-host "Getting DCs not owned by Domain Admins"

$count = 0
$progresscount = 0
# Get all domain controllers by filtering based on their group memberships (PrimaryGroupID for DCs is 516 or 521)
$domaincontrollers = Get-DomainComputer -Domain $domain -LDAPFilter "(&(objectClass=computer)(|(primaryGroupID=516)(primaryGroupID=521)))" -Properties Name, dnshostname, ntsecuritydescriptor, operatingSystem, operatingSystemServicePack, operatingSystemVersion, ipv4Address -ErrorAction SilentlyContinue
$totalcount = ($domaincontrollers | Measure-Object).Count
    
if ($totalcount -gt 0) {
    ForEach ($machine in $domaincontrollers) {
        $progresscount++
        # Display progress of the search
        Write-Progress -Activity "Searching for DCs not owned by Domain Admins group..." -Status "Currently identified $count" -PercentComplete ($progresscount / $totalcount * 100)
            
        # Check if the machine's security descriptor has an owner and verify it
        if ($machine.ntsecuritydescriptor -and $machine.ntsecuritydescriptor.Owner -notlike "*Domain Admins*") {
            # Prepare the output with detailed information
            $output = @{
                'ComputerName' = $machine.Name
                'DNSHostName' = $machine.dnshostname
                'OperatingSystem' = $machine.OperatingSystem
                'ServicePack' = $machine.OperatingSystemServicePack
                'OSVersion' = $machine.OperatingSystemVersion
                'IPv4Address' = $machine.IPv4Address
                'OwnedBy' = $machine.ntsecuritydescriptor.Owner
            }
            # Display the information in a readable format
            $output | Format-Table -AutoSize | Export-Csv -NoTypeInformation -Append DCs_Not_Owned_By_DAs_$domain.csv
            $count++
        } else {
            # Output if the ownership information is missing or unclear
            Write-Output "Ownership information missing or belongs to Domain Admins for $($machine.Name). So not an issue here."
        }
    }
} else {
    Write-Host "No domain controllers found."
}

write-host "" #>

# Number of Enterprise Administrator Accounts Above the Baseline (Non-Default Admins)
Write-Host "Getting number of Enterprise Admin accounts above baseline i.e. non-default admins... "
Write-Host "There should be no users used on a day-to-day basis in this group, with the possible exception of the root domain's Administrator account. https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-e--securing-enterprise-admins-groups-in-active-directory"
# old way
#Get-DomainGroupMember -Domain $domain -Identity $(ConvertFrom-SID "S-1-5-32-544") -ErrorAction SilentlyContinue | Export-Csv -NoTypeInformation -Append Admins_Other_Than_Default_Administrator_User_$domain.csv

# new way
# SID for the "Enterprise Admins" group (same across all domains)

$enterpriseAdminsSID = ConvertFrom-SID "$(Get-DomainSID)-519"

# SID for the "Administrators" group (same across all domains)

$rootAdminGroupSID = "S-1-5-32-544"

# Initialize an array to store results

$nonCompliantAdmins = @()


# Get members of the Enterprise Admins group for the current domain
$allEnterpriseAdminMembers = Get-DomainGroupMember -Domain $domain -Identity $enterpriseAdminsSID -ErrorAction SilentlyContinue

foreach ($member in $allEnterpriseAdminMembers) {

$memberSID = $member.MemberSID

# Check if the member SID matches the root domain's Administrator group SID

if ($memberSID -ne $rootAdminGroupSID) {

    # Check if the member is a user account (we're ignoring service or other types)

    if ($member.memberobjectClass -eq 'user') {

        # Flag this non-compliant member

        $nonCompliantAdmins += [pscustomobject]@{

            EnterpriseAdminsGroupDomain = $domain

            SamAccountName = $member.MemberName

            MemberSID = $memberSID

            userMemberOfDomain = $member.memberdomain

            }

        }

    }

}

# Output or export the non-compliant members
if ($nonCompliantAdmins.Count -gt 0) {

    Write-Output "The following user(s) are in the Enterprise Admins group across the domains, which should not be used on a day-to-day basis:"

    $nonCompliantAdmins | Format-Table -AutoSize

    # Optionally export to CSV:
    $nonCompliantAdmins | Export-Csv -Path "Non_Compliant_Enterprise_Admins_Group_$($domain).csv" -NoTypeInformation

} else {
    Write-Output "No non-compliant user accounts found in the Enterprise Admins group across all domains."

}

write-host ""

# Admins with SPN
write-host "Getting admins with SPNs"
Get-NetUser -admincount -SPN -domain $domain -ErrorAction SilentlyContinue | select name | Export-Csv -NoTypeInformation -Append Admins_with_SPN_$domain.csv
write-host ""

# Enabled Admins with password expiry disabed
write-host "Getting enabled admins with pwd expiry disabled"
Get-DomainUser -admincount -Domain $domain -ErrorAction SilentlyContinue | ?{$_.useraccountcontrol -notmatch "ACCOUNTDISABLE" -and $_.useraccountcontrol -match "DONT_EXPIRE_PASSWORD"} | select samaccountname | Export-Csv -NoTypeInformation -Append Admins_with_Password_Expiry_Disabled_$domain.csv
write-host ""

# Get inactive/dormant accounts
write-host "Getting inactive/dormant accounts (users and computers)"
$domainc = Get-DomainController -Domain $domain | select -first 1 -ExpandProperty name
## Users
Search-ADAccount -AccountInactive -UsersOnly -TimeSpan 180:00:00:00 -Server $domainc -ErrorAction SilentlyContinue | ?{$_.Enabled -eq $True} | Select userprincipalname | Export-Csv -NoTypeInformation -Append Inactive_Dormant_User_Accounts_$domain.csv

## Computers
Search-ADAccount -AccountInactive -ComputersOnly -TimeSpan 180:00:00:00 -Server $domainc -ErrorAction SilentlyContinue | ?{$_.Enabled -eq $True} | Select samaccountname | Export-Csv -NoTypeInformation -Append Inactive_Dormant_Computer_Accounts_$domain.csv
write-host ""

# Get admins where password last set more than 3 years ago
# Define the cutoff date (3 years ago from today)
$cutoffDate = (Get-Date).AddYears(-3)

Get-DomainUser -domain $domain -AdminCount -ErrorAction SilentlyContinue | Where-Object {  $_.PwdLastSet -lt $cutoffDate  } | Select-Object samaccountname, PwdLastSet | Export-Csv -NoTypeInformation -Append admins_pwd_last_set_more_than_3_years_ago_$domain.csv
write-host ""

# Not all priv accounts are Protected Users
$allAccountsNotProtected = @()
 
# Create a DirectoryEntry object for the domain
$domainEntry = New-Object DirectoryServices.DirectoryEntry("LDAP://$domain")
 
# Retrieve the domain SID dynamically using Get-DomainSID
$domainSID = $(Get-DomainSID)
 
# Create a DirectorySearcher object to query AD for privileged groups by SID
$searcher = New-Object DirectoryServices.DirectorySearcher($domainEntry)
 
# Replace CN filters with SID filters for privileged groups, using $domainSID
$searcher.Filter = "(|(objectSID=$domainSID-512)(objectSID=$domainSID-519)(objectSID=$domainSID-518)(objectSID=$domainSID-544))"
$searcher.SearchScope = "Subtree"
$searcher.PropertiesToLoad.AddRange(@("member"))
 
# Collect the results
$results = $searcher.FindAll()
 
# Get the 'Protected Users' group distinguished name by SID, using $domainSID
$protectedUsersSearcher = New-Object DirectoryServices.DirectorySearcher($domainEntry)
 
# Protected Users SID: e.g., S-1-5-21-<domain>-525
$protectedUsersSearcher.Filter = "(objectSID=$domainSID-525)"
$protectedUsersSearcher.PropertiesToLoad.Add("distinguishedName")
 
# Try to find the Protected Users group
$protectedUsersResult = $protectedUsersSearcher.FindOne()
 
# Check if the Protected Users group was found
if ($protectedUsersResult -ne $null -and $protectedUsersResult.Properties["distinguishedname"].Count -gt 0) {
    $protectedUsersDN = $protectedUsersResult.Properties["distinguishedname"][0]
} else {
    Write-Warning "Protected Users group not found in the domain. Exiting script."
    #return
}
 
# Initialize an array for accounts not in 'Protected Users' for this domain
$accountsNotProtected = @()
 
# Loop through the results and check if they are members of the 'Protected Users' group
foreach ($result in $results) {
    $members = $result.Properties["member"]
 
    foreach ($memberDN in $members) {
        $memberSearcher = New-Object DirectoryServices.DirectorySearcher($domainEntry)
        $memberSearcher.Filter = "(distinguishedName=$memberDN)"
        $memberSearcher.PropertiesToLoad.Add("samaccountname")
        $memberSearcher.PropertiesToLoad.Add("memberof")
 
        $memberResult = $memberSearcher.FindOne()
 
        if ($memberResult -and $memberResult.Properties["memberof"] -notcontains $protectedUsersDN) {
            $accountsNotProtected += [pscustomobject]@{
                UserName = $memberResult.Properties["samaccountname"][0]
                DistinguishedName = $memberDN
                GroupName = $result.Path.Split('/')[-1].Replace("CN=", "")
                Domain = $domain
            }
        }
    }
}
 
# Add the results for this domain to the global list
$allAccountsNotProtected += $accountsNotProtected
 
# Output the result
if ($allAccountsNotProtected.Count -eq 0) {
    Write-Output "All privileged accounts are members of the 'Protected Users' group across all domains."
} else {
    Write-Warning "The following privileged accounts are NOT members of the 'Protected Users' group:"
    $allAccountsNotProtected | Format-Table UserName, GroupName, DistinguishedName, Domain
}

# Export the results to a CSV file
$allAccountsNotProtected  | Export-Csv -Path "Not_Protected_Accounts_$domain.csv" -NoTypeInformation -Append
write-host ""

# Insecure AD Trust Configuration
write-host "Checking Insecure AD Trust Configuration"
Get-DomainTrust -Domain $domain -ErrorAction SilentlyContinue -Server $(Get-DomainController -Domain $domain -ErrorAction SilentlyContinue | select -first 1 -ExpandProperty IPAddress) | ? { $_.TrustAttributes -like "*TREAT_AS_EXTERNAL*" } | Export-Csv -Path "Insecure_AD_Trust_Config_$domain.csv" -NoTypeInformation -Append
write-host ""

# Use of Kerberos with Weak Encryption (Not AES)
write-host "Checking use of Kerberos with weak encryption algorithms (Not AES)"
write-host "Number to Algorithm mappings can be found online / in PingCastle if interested/needed. Or here even: https://techcommunity.microsoft.com/blog/coreinfrastructureandsecurityblog/decrypting-the-selection-of-supported-kerberos-encryption-types/1628797"
#Get-ADObject -Domain $domain -Filter {UserAccountControl -band 0x200000 -or msDs-supportedEncryptionTypes -band 3}  | Export-Csv -Path "kerberos_with_weak_encryption_supported_des_method_1_$domain.csv" -NoTypeInformation -Append
#Get-DomainObject -Domain $domain -LDAPFilter "(&(objectClass=user)(|(msDs-supportedEncryptionTypes:1.2.840.113556.1.4.803:=1)(msDs-supportedEncryptionTypes:1.2.840.113556.1.4.803:=2)))" -Properties SamAccountName, msDs-supportedEncryptionTypes | Select-Object SamAccountName, msDs-supportedEncryptionTypes  | Export-Csv -Path "kerberos_with_weak_encryption_supported_des_method_2_$domain.csv" -NoTypeInformation -Append
$encTypes = @(
    "Not defined - defaults to RC4_HMAC_MD5",
    "DES_CBC_CRC",
    "DES_CBC_MD5",
    "DES_CBC_CRC | DES_CBC_MD5",
    "RC4",
    "DES_CBC_CRC | RC4",
    "DES_CBC_MD5 | RC4",
    "DES_CBC_CRC | DES_CBC_MD5 | RC4",
    "AES 128",
    "DES_CBC_CRC | AES 128",
    "DES_CBC_MD5 | AES 128",
    "DES_CBC_CRC | DES_CBC_MD5 | AES 128",
    "RC4 | AES 128",
    "DES_CBC_CRC | RC4 | AES 128",
    "DES_CBC_MD5 | RC4 | AES 128",
    "DES_CBC_CBC | DES_CBC_MD5 | RC4 | AES 128",
    "AES 256",
    "DES_CBC_CRC | AES 256",
    "DES_CBC_MD5 | AES 256",
    "DES_CBC_CRC | DES_CBC_MD5 | AES 256",
    "RC4 | AES 256",
    "DES_CBC_CRC | RC4 | AES 256",
    "DES_CBC_MD5 | RC4 | AES 256",
    "DES_CBC_CRC | DES_CBC_MD5 | RC4 | AES 256",
    "AES 128 | AES 256",
    "DES_CBC_CRC | AES 128 | AES 256",
    "DES_CBC_MD5 | AES 128 | AES 256",
    "DES_CBC_MD5 | DES_CBC_MD5 | AES 128 | AES 256",
    "RC4 | AES 128 | AES 256",
    "DES_CBC_CRC | RC4 | AES 128 | AES 256",
    "DES_CBC_MD5 | RC4 | AES 128 | AES 256",
    "DES+A1:C33_CBC_MD5 | DES_CBC_MD5 | RC4 | AES 128 | AES 256"
)

# Get all users with the msDS-SupportedEncryptionTypes attribute
$EncVal = Get-DomainUser -Domain $domain -Properties SamAccountName, msDS-SupportedEncryptionTypes -ErrorAction SilentlyContinue

# Initialize an array to store results
$results = @()

$atLeastOneAccountNotConfiguredToAES256 = $false

# Loop through each user and process encryption types
foreach ($e in $EncVal) {
    try {
        # Get the encryption types value
        $encValue = $e.'msDS-SupportedEncryptionTypes'

        # Check if the value exists and map it to the corresponding encryption type
        $encryptionType = if ($encValue -ne $null) {
            $encTypes[$encValue]
            if($encValue -ne "16"){
                $atLeastOneAccountNotConfiguredToAES256 = $true
            }
        } else {
            $encTypes[0]  # Default if no encryption type is defined
        }

        # Create a custom object with SamAccountName, encryption type, and raw encryption value
        $results += [pscustomobject]@{
            SamAccountName = $e.SamAccountName
            EncryptionType = $encryptionType
            EncryptionValue = $encValue
        }
    } catch {
        # If there's an error, return the default encryption type
        $results += [pscustomobject]@{
            SamAccountName = $e.SamAccountName
            EncryptionType = $encTypes[0]
            EncryptionValue = "Error or Undefined"
        }
    }
}

if($atLeastOneAccountNotConfiguredToAES256){
    Write-Host "There's at least one account which isn't configured solely to AES 256. So recommend writing this one up." -ForegroundColor Yellow
}

# Export the results to a CSV file
$results | Export-Csv -Path "User_Accounts_Kerberos_Encryption_Configuration_$($domain).csv" -NoTypeInformation -Append

write-host ""

# Hidden group memberships for user accounts
write-host "Not checking hidden group memberships for user accounts. It's commented out, so just amend the script and uncomment this to run the check. Probs wont work." -ForegroundColor Cyan
#Get-ADUser -Filter * -Properties PrimaryGroup | Where-Object { $_.PrimaryGroup -ne (Get-ADGroup -Identity "Domain Users").DistinguishedName } | Select-Object UserPrincipalName,PrimaryGroup  | Export-Csv -Path "Hidden_Group_Memberships_For_User_Accounts_$domain.csv" -NoTypeInformation -Append
#write-host ""

# Excessive Foreign Group Memberships
write-host "Checking excessive foreign group memberships"
Get-DomainForeignGroupMember -Domain $domain | select @{Name="membername"; Expression={ $_.membername }},@{Name="membername_sid_converted"; Expression={ ([System.Security.Principal.SecurityIdentifier]::new($_.membername).Translate([System.Security.Principal.NTAccount])).Value }} | Export-Csv -Path "Excessive_Foreign_Group_Membership_SID_Converted_to_Name_$domain.csv" -NoTypeInformation -Append
write-host ""

<#
# Password expiration disabled for domain admins group
Write-Host "Checking Password expiration disabled for domain admins group"
Get-DomainGroupMember -Domain $domain -Identity $(ConvertFrom-SID "$(Get-DomainSID)-512") | ForEach-Object {
     # Get user properties including userAccountControl and group memberships
     Get-DomainUser -Domain $domain -Identity $_.SamAccountName -Properties samaccountname, userAccountControl, MemberOf | Where-Object {
         # Filter for accounts with Password Never Expires flag set and in Domain Admins group
         ($_.userAccountControl -band 0x10000) -and ($_.useraccountcontrol -notlike "*ACCOUNTDISABLE*") -and ($_.MemberOf -match $(ConvertFrom-SID "$(Get-DomainSID)-512").samaccountname)
     } | Select-Object SamAccountName, userAccountControl | Sort-Object SamAccountName -Unique |  Export-Csv -Path "password_expiration_disabled_for_domain_admins_group_$domain.csv" -NoTypeInformation -Append
}#>

# Constrained Delegation
Write-Host "Traditional Constrained Delegation check"
Get-DomainUser -Trustedtoauth -Domain $domain -ErrorAction SilentlyContinue | Where-Object {  $_.UserAccountControl -notmatch 'NOT_DELEGATED' -and $_.UserAccountControl -notmatch 'ACCOUNTDISABLE' } | select displayname, useraccountcontrol, msds-allowedtodelegateto | Export-Csv -Path "Traditional_Constrained_Delegation_Configured_Users_$domain.csv" -NoTypeInformation -Append
write-host ""

# Unknown account in delegation
Write-Host "Unknown Account in Delegation Check"
Get-DomainComputer -Domain $domain -Filter {TrustedForDelegation -eq $true -and primarygroupid -eq 515} -Properties trustedfordelegation,serviceprincipalname,description -ErrorAction SilentlyContinue | Export-Csv -Path "Unknown_Account_in_Delegation_$domain.csv" -NoTypeInformation -Append
write-host ""

# Get objects with Unconstrained Delegation
Get-DomainComputer -Unconstrained -Domain $domain | Select-Object SamAccountName | Export-Csv -Path "Unconstrained_Delegation_Computers_$domain.csv" -NoTypeInformation -Append
Get-DomainUser -AllowDelegation -AdminCount -Domain $domain  | Select-Object SamAccountName | Export-Csv -Path "Unconstrained_Delegation_Users_$domain.csv" -NoTypeInformation -Append
write-host ""

# Accounts which can have an empty password set
Write-Output "User accounts which can have an empty password set:"
Write-Host "Checking users"
Get-DomainUser -Domain $domain -Properties samaccountname,displayname,useraccountcontrol -ErrorAction SilentlyContinue | Where-Object {  $_.UserAccountControl -match 'PASSWD_NOTREQD' -and $_.UserAccountControl -notmatch 'ACCOUNTDISABLE' } | select samaccountname,displayname, useraccountcontrol | Export-Csv -Path "user_accounts_empty_passwords_allowed_$domain.csv" -NoTypeInformation -Append
Write-Output "Computer accounts which can have an empty password set:"
Write-Host "Checking computers"
Get-DomainComputer -Domain $domain -Properties samaccountname,displayname,useraccountcontrol -ErrorAction SilentlyContinue | Where-Object {  $_.UserAccountControl -match 'PASSWD_NOTREQD' -and $_.UserAccountControl -notmatch 'ACCOUNTDISABLE' } | select samaccountname,displayname, useraccountcontrol | Export-Csv -Path "computer_accounts_empty_passwords_allowed_$domain.csv" -NoTypeInformation -Append

write-host ""

# vulnerable schema class check
Write-Host "Vulnerable Schema Class check"
# Vulnerable Schema Class
$allVulnerableSchemas = @()
# Create a dictionary to hold superclass names

$superClass = @{}

# List to hold class names that inherit from container and are allowed to live under computer object

$vulnerableSchemas = [System.Collections.Generic.List[string]]::new()

# Create a DirectoryEntry object to connect to the Global Catalog (GC) for the domain

$schemaEntry = New-Object DirectoryServices.DirectoryEntry("GC://$domain")

# Create a DirectorySearcher object to enumerate all class schemas

$searcher = New-Object DirectoryServices.DirectorySearcher($schemaEntry)

$searcher.Filter = "(objectClass=classSchema)"

$searcher.SearchScope = "Subtree"

$searcher.PropertiesToLoad.AddRange(@("lDAPDisplayName", "subClassOf", "possSuperiors"))

# Collect the results
try{
$classSchemas = $searcher.FindAll()
}catch{}
# Enumerate all class schemas that the computer is allowed to contain

$computerInferiors = @()

foreach ($schema in $classSchemas) {

    if ($schema.Properties["posssuperiors"] -contains "computer") {

        $computerInferiors += $schema

    }

}

# Populate superclass table

foreach ($schema in $classSchemas) {

    $ldapDisplayName = $schema.Properties["lDAPDisplayName"]

    $subClassOf = $schema.Properties["subClassOf"]

    if ($ldapDisplayName -and $subClassOf) {

        $superClass[$ldapDisplayName[0]] = $subClassOf[0]

    }

}

# Resolve class inheritance for computer inferiors

foreach ($inferior in $computerInferiors) {

    $class = $cursor = $inferior.Properties["lDAPDisplayName"][0]

    while ($superClass[$cursor] -ne $null -and $superClass[$cursor] -ne "top") {

        if ($superClass[$cursor] -eq "container") {

            $vulnerableSchemas.Add($class)

            break

        }

        $cursor = $superClass[$cursor]

    }

}

# Store the results for this domain

foreach ($schema in $vulnerableSchemas) {

    $allVulnerableSchemas += [pscustomobject]@{

        Domain = $domain

        VulnerableSchema = $schema

    }

}

# Output the list of vulnerable class schemas across all domains
$allVulnerableSchemas | select Domain,VulnerableSchema |  Export-Csv -Path "c:\temp\Vulnerable_Schema_Class_$domain.csv" -NoTypeInformation -Append

Write-Host "These next checks take a while without limiting how many objects are selected. Amend the script if you'd like to view all results, otherwise, only some of the output will be returned as a PoC of the finding."

<#
Write-Host "Ok, now we're about to start checks that can take quite a while. You've got the majority of the checks covered already." -ForegroundColor Cyan
$choice = $null

do {
    $input = Read-Host "Do you want to continue with these longer checks or skip them and move on to the next domain (if there's another to check)? (Y/N): "
    if ($input -match '^(?i)[y]$'){
        Write-Host "Continuing with potentially longer checks" -ForegroundColor Green
    }elseif ($input -match '^(?i)[n]$'){
        Write-Host "Not continuing with potentially longer checks. Checking next domain if there's another to check." -ForegroundColor Yellow
        $choice = "N"
        break
    }else{
        Write-Host "Invalid input. Please enter Y or N." -ForegroundColor Red
    }
} while ($true)

if($choice.toupper() -eq "N"){
    break
}

Write-Host "Here we go..." -ForegroundColor Cyan
#>

# Insecure Storage of Sensitive Information
write-host "Checking Insecure Storage of Sensitive Information (file names)"
write-host "Warning, only 5 objects are being returned for each domain in this script. Amend the script if you want more checked. We're just proving the issue exists here."
Find-InterestingDomainShareFile -DomainController $(Get-DomainController -Domain $domain -ErrorAction SilentlyContinue | select -first 1 -ExpandProperty IPAddress)  -Include @("*password*","*admin*","*login*","*secret*","*unattend*.xml","*creds*","*credential*","*database*") | select -First 5 | Export-Csv -Path "interesting_file_names_on_shares_$domain.csv" -NoTypeInformation -Append
write-host ""

# Overly Permissive ACLs (GenericAll)
Write-Host "Checking objects with GenericAll (overly permissive ACLs)" -ForegroundColor Yellow
write-host "Warning, only 5 objects are being returned for each domain in this script. Amend the script if you want more checked. We're just proving the issue exists here."
#Get-DomainObjectACL -Domain $domain -ErrorAction SilentlyContinue | Where-Object { $_.ActiveDirectoryRights -eq "GenericAll" } | select -First 5 | Select-Object -ExpandProperty SecurityIdentifier | ForEach-Object { Convert-SidToName -ObjectSid $_ } | Export-Csv -Path "GenericAll_ACLs_Overly_Permissive_$domain.csv" -NoTypeInformation -Append
Get-DomainObjectACL -Domain $domain -ErrorAction SilentlyContinue |
     Where-Object { $_.ActiveDirectoryRights -eq "GenericAll" } |
     Select-Object -First 5 |
     Select-Object -ExpandProperty SecurityIdentifier |
     ForEach-Object {
         $sidName = Convert-SidToName -ObjectSid $_
         [pscustomobject]@{
             SIDName = $sidName
         }
     } |
     Select-Object -Unique | Export-Csv -Path "GenericAll_ACLs_Overly_Permissive_$domain.csv" -NoTypeInformation -Append

Write-Host ""

# Net session enum permitted
write-host "Determining if net session enum is permitted. Could take a while."
write-host "Warning, only 10 domain-joined computers are being checked for each domain in this script. Amend the script if you want more checked. We're just proving the issue exists here."
Get-DomainComputer -Domain $domain -ErrorAction SilentlyContinue  | select -first 10 | Get-NetSession |  Export-Csv -Path "Net_Session_Enum_Permitted_$domain.csv" -NoTypeInformation -Append
write-host ""

write-host ""
write-host "All done I believe for domain $domain." -ForegroundColor Green
date
}

Write-Host "Clearing empty CSV files in current working directory: $($pwd.path)." -ForegroundColor Yellow
gci *.csv -ErrorAction SilentlyContinue | ? {$_.Length -eq 0} | Remove-Item -Force -ErrorAction SilentlyContinue
Write-Host "Cleared empty CSV files in current working directory." -ForegroundColor Yellow
Write-Host "Finished all domains AFAIK. Done."-ForegroundColor Green
date
Write-Host ""