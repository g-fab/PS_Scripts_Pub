import-module activedirectory
Get-ADUser -Filter * -SearchBase "OU=USERS,DC=mydomain,DC=com" | Where { $_.Enabled -eq $True} | Select -Property SamAccountName | ForEach-Object { $_.SamAccountName } | Out-File -FilePath "D:\SCAN\Users.txt" -Encoding UTF8
$Users = Get-Content "D:\SCAN\Users.txt" -Encoding UTF8 | ForEach-Object {$_ -replace '"',''}
ForEach ($user in $users)
{
$newPath = Join-Path "D:\SCAN\" -childpath $user
New-Item $newPath -type directory 
$acl = Get-acl $newPath
$permission = "mydomain\$user","FullControl",'ContainerInherit,ObjectInherit', 'None', 'Allow'
$accessRule = New-Object System.Security.AccessControl.FileSystemAccessRule $permission
$acl.SetAccessRule($accessRule)
$acl.SetAccessRuleProtection($true,$true)
$acl | Set-Acl $newPath

$acl = Get-acl $newPath
$permission = "mydomain\AllUsers","ListDirectory","Allow"
$accessRule = New-Object System.Security.AccessControl.FileSystemAccessRule $permission
$acl.RemoveAccessRuleAll($accessRule)
$acl | Set-Acl $newPath



# find home directory for scan folder
$fileServer = switch -regex ($user) {
        '^[a-m][^0]' { "fs-users01" }
        '^[n-z][^0]' { "fs-users02" }
           }
$homedir = "\\$fileServer\users\$user"
$oldscanfolder = "$homedir\scan"
Copy-Item -Recurse -Path $oldscanfolder -Destination $newpath

    }
