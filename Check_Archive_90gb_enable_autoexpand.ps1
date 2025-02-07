# Récupérer les utilisateurs avec des archives actives
$userstop90 = Get-Mailbox -ResultSize Unlimited -RecipientTypeDetails UserMailbox | Where-Object { $_.ArchiveStatus -eq "Active" }

# Boucle pour vérifier la taille des archives
foreach ($usertop in $userstop90) {
    # Récupérer les statistiques de la boîte aux lettres d'archive
    $archiveStats = Get-MailboxStatistics -Archive $usertop.PrimarySmtpAddress
    
    # Extraire la taille en octets et en Go
    $archiveSizeString = $archiveStats.TotalItemSize.ToString()
    
    # Utiliser une expression régulière pour extraire les valeurs
    if ($archiveSizeString -match '(\d+\.?\d*)\s*GB') {
        $archiveSizeGB = [double]$matches[1]
    } elseif ($archiveSizeString -match '(\d+)\s*bytes') {
        $archiveSizeBytes = [long]$matches[1]
        $archiveSizeGB = [math]::Round($archiveSizeBytes / 1GB, 2)
    } else {
        Write-Host "Erreur lors de l'extraction de la taille d'archive pour $($usertop.DisplayName)"
        continue
    }

    # Vérifier si la taille est supérieure à 90 Go
    if ($archiveSizeGB -gt 90) {
        Write-Host "$($usertop.DisplayName) a une archive de taille supérieure à 90 Go"
        # Activer l'archive automatique (avec -WhatIf pour simulation)
        Enable-Mailbox -Identity $usertop.PrimarySmtpAddress -AutoExpandingArchive -WhatIf
        Write-Host "Archive automatique serait activée pour $($usertop.DisplayName)"
    }
}
