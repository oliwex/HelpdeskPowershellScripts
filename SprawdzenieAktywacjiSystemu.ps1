# Pobranie listy stacji roboczych z pliku
$listaStacji = Get-Content -Path "lista_stacji.txt"

# Przejście przez każdą stację roboczą
foreach ($stacja in $listaStacji) {
    Write-Host "Sprawdzanie stacji roboczej: $stacja"
    
    # Sprawdzenie statusu aktywacji
    $status = (Invoke-Command -ComputerName $stacja -ScriptBlock {
        $activationStatus = Get-WmiObject -Query "SELECT LicenseStatus FROM SoftwareLicensingProduct WHERE PartialProductKey IS NOT NULL" | Select-Object -First 1
        if ($activationStatus.LicenseStatus -eq 1) {
            return "Aktywowany"
        } else {
            return "Nieaktywowany"
        }
    })
    
    # Wyświetlenie wyniku
    Write-Host ("Status aktywacji na stacji {0}: {1}" -f $stacja, $status)
    
    # Zapisanie wyniku do pliku
    $wynik = "{0} {1}" -f $stacja, $status
    $wynik | Out-File -FilePath "wyniki.txt" -Append
}

Write-Host "Proces sprawdzania aktywacji został zakończony."
