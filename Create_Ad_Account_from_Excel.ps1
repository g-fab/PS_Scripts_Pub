# Set variables
$pathToOU = "OU=USERS,DC=domain,DC=local"
$users = Import-Excel -Path 'C:\Users\myuser\Desktop\accounts.xlsx' -StartColumn "2" -EndColumn "12" -StartRow "4" -EndRow "5" #change endrow according the number of line in the file

# Loop through users
foreach ($user in $users) {
    $prenom = $user.prenom
    $nom = $user.nom
    $samaccountname = $prenom.ToLower()[0] + $nom.ToLower()
    $cn = $nom.ToUpper() + " " + $prenom.Substring(0,1).toupper()+$prenom.substring(1)
    $userprincipalname = "$samaccountname@domain.com"
    $secpasswd = ConvertTo-SecureString -String "P@$$w0rd" -AsPlainText -Force
    $company = "Company"
    $department = $user.direction
    $wWWHomePage = $user.matricule
    $title = $user.poste
    $contrat = $user.contrat
    $AccountExpirationDate = $user.DATE_FIN
    $manager = $user.MANAGER
    $licence = $user.LICENCE
    $site = $user.site
    $datedefin = $user.DATE_FIN
    #$newdate = [Datetime]::ParseExact($datedefin, 'dd/MM/yyyy', $null)

# Create user
    $newUserParams = @{
        Name = $cn
        Path = $pathToOU
        Enabled = $true
        AccountPassword = (ConvertTo-SecureString -AsPlainText $secpasswd -Force)
        SamAccountName = $samaccountname
        UserPrincipalName = $userprincipalname
        EmailAddress = $userprincipalname
        GivenName = $prenom
        Surname = $nom
        Title = $title
        Company = $company
        Department = $department
        DisplayName = $cn
        HomePage = $wWWHomePage
        Manager = $manager
        Office = $site
    }


    if ($contrat -like "cdi") {
        New-ADUser @newUserParams 
    } else {
        $newdate = [DateTime]::ParseExact($user.DATE_FIN, 'dd/MM/yyyy', $null)
        $newUserParams.Add('AccountExpirationDate', $newdate.AddDays(1))
        New-ADUser @newUserParams
    }
	



# Afficher le resultat
write-host "Le compte $userprincipalname a été crée. son mot de passe est: $secpasswd" -ForegroundColor Green


# Create home directory
    $fileServer = switch -regex ($samaccountname) {
        '^[a-m][^0]' { "srv-users01" }
        '^[n-z][^0]' { "srv-users02" }
    }
    $homedir = "\\$fileServer\users\$samaccountname"

#Création du dossier HomeDir
New-Item -ItemType Directory -Path $homedir

Start-Sleep -s 30

#disable inheritance sur le homedir
$folder = $homedir
$acl = Get-ACL -Path $folder
$acl.SetAccessRuleProtection($True, $True)
Set-Acl -Path $folder -AclObject $acl


#attribution des droits sur le homedir
Write-Output -InputObject "domain\$samAccountName"
$rule = New-Object System.Security.AccessControl.FileSystemAccessRule("domain\$samAccountName","FullControl", "ContainerInherit, ObjectInherit", "None", "Allow")
$Acl.addAccessRule($rule)
$acl | Set-Acl


# Create scan directory
$scanPath = "\\scanshare\scan\$samaccountname\scan"
New-Item -ItemType Directory -Path $scanPath 

Start-Sleep -s 30

#disable inheritance sur le dossier scan
$folder2 = "\\scanshare\scan\$samaccountname"
$acl = Get-ACL -Path $folder2
$acl.SetAccessRuleProtection($True, $True)
Set-Acl -Path $folder2 -AclObject $acl


#attribution des droits sur le dossier scan

$acl3 = Get-Acl -Path $folder2
Write-Output -InputObject "domain\$samaccountname"
$accessRule = New-Object System.Security.AccessControl.FileSystemAccessRule("domain\$samAccountName","FullControl", "ContainerInherit, ObjectInherit", "None", "Allow")
$acl3.SetAccessRule($accessRule)
$acl3 | Set-Acl



#ajout custom attribute cap15 pour ajout list distrib dyn
if ($site -like "site1")
{
set-aduser -Identity $samAccountName -replace @{ExtensionAttribute8="site1"}
}

#Attribution licence
if ($licence -like "basic")
{ 
Add-ADGroupMember -Identity "365_licence_E1_Sans_Teams" -Members $samaccountname
Write-Host "licence basic attribuée à $samaccountname" -ForegroundColor Green
}
else
{
Add-ADGroupMember -Identity "365_Licence_Premium" -Members $samaccountname
Write-Host "licence premium attribuée à $samaccountname" -ForegroundColor Green
}

#add group map FS
$FSgroup = switch -regex ($samaccountname) {
        '^[a-m][^0]' { "map_homedir_srv-users01" }
        '^[n-z][^0]' { "map_homedir_srv-users02" }
    }
Add-ADGroupMember -Identity $FSgroup -Members $samaccountname


