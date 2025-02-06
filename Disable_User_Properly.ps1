$userslist = Import-Excel -Path .\sortis.xlsx -StartColumn "2" -EndColumn "3" -StartRow "4" -EndRow "5" #changer endrow en fonction du nombre de lignes
foreach ($user in $userslist)
{

    $nom = $user.Nom
    $prenom = $user.Prenom
    $samtodisable = $prenom[0] + $nom
    $sam = $samtodisable.ToString()
    $dn = Get-ADUser -Identity $sam -Properties * | select distinguishedname


#désactiver son compte AD
    Disable-ADAccount -Identity $sam -Confirm:$false
    Write-Host "User $sam disabled" -foregroundcolor green


#supprimer son appartenance aux groupes
    Get-AdPrincipalGroupMembership -Identity $sam | Where-Object -Property Name -Ne -Value 'Utilisa. du domaine' | Remove-AdGroupMember -Members $sam -Confirm:$false
    Write-Host "$sam removed from groups" -foregroundcolor green




#definir le mailnickname et mettre le sam
    $lol = get-aduser -identity $sam
    Set-ADUser -Identity $dn  -Replace @{mailNickname=$lol.sam}
    Write-Host "MailNickName set to $sam" -foregroundcolor green


#definir hide from address list
    Set-ADObject -identity $dn -replace @{msExchHideFromAddressLists=$true}
    Set-ADObject -identity $dn -clear ShowinAddressBook
    Write-Host "$sam hidden from addressBook" -foregroundcolor green

#delete extensionAttribute8 and office location
    if (get-aduser -identity $sam | select extensionAttribute8) {
    set-adobject -Identity $dn -clear extensionAttribute8
    set-adobject -Identity $dn -clear physicalDeliveryOfficeName
    set-adobject -Identity $dn -clear proxyAddresses
    set-adobject -Identity $dn -clear mail
    set-adobject -Identity $dn -clear legacyExchangeDN
     }


#supprimer le matricule
    Set-ADObject -identity $dn -clear wWWHomePage

#Move disabled user to Disabled OU 
    Move-ADObject -Identity (Get-ADuser $sam) -TargetPath 'OU=Disabled_Users,DC=domain,DC=com'
    Write-Host "$sam moved to Disabled Users" -foregroundcolor green


# locate home directory
    $fileServer = switch -regex ($sam) {
        '^[a-m][^0]' { "fileserver01" }
        '^[n-z][^0]' { "fileserver02" }
            }


    $homedir = "\\$fileServer\users\$sam"

    $destination = "\\bckpserv\x$\homedirs"
        if (Test-Path -Path $homedir) {
                move-item -Path $homedir -Destination $destination\$sam -Force 
                Write-Progress -Activity "moving files" 
                Write-Host "$sam Home Drive archived to $destination\$sam" -foregroundcolor green
             }

#suppression repertoire Scan sur gutenberg
    if (test-path \\scanshare\scan\$sam) {
    remove-item -Path "\\scanshare\scan\$sam" -Force -Confirm:$false -Recurse
    Write-Progress -Activity "moving files" 
    Write-Host "$sam Scan folder deleted"  -foregroundcolor green
    }


}

