$lama="computer"
 #TODO: ID40

 foreach($lam in $lama)
 {

Get-WinEvent -LogName 'Microsoft-Windows-TerminalServices-LocalSessionManager/Operational' -ComputerName $lam | Select-Object ID,MachineName,TimeCreated,Message | ForEach-Object {
    $message=$($_.Message).Split("`n")

    if ($_.ID -eq 21)
    {
        [PSCustomObject]@{
            COMPUTER = $($_.MachineName)
            EVENT_TIME = $($_.TimeCreated)
            MESSAGE ="LOGOWANIE POWIODLO SIE"
            USER = ($message[2]).Split(":").Trim()[1]
            SESSION_ID=($message[3]).Split(":").Trim()[1]
            SOURCE_IP=$(($message[4]).Split(":").Trim()[1])
        }
    }
    elseif ($_.ID -eq 22) 
    {
        [PSCustomObject]@{
            COMPUTER = $($_.MachineName)
            EVENT_TIME = $($_.TimeCreated)
            MESSAGE ="POWLOKA URUCHOMIONA"
            USER = ($message[2]).Split(":").Trim()[1]
            SESSION_ID=($message[3]).Split(":").Trim()[1]
            SOURCE_IP=$(($message[4]).Split(":").Trim()[1])
        }
    }
    elseif ($_.ID -eq 23)
    {
        [PSCustomObject]@{
            COMPUTER = $($_.MachineName)
            EVENT_TIME = $($_.TimeCreated)
            MESSAGE ="WYLOGOWANIE POWIODLO SIE"
            USER = ($message[2]).Split(":").Trim()[1]
            SESSION_ID=($message[3]).Split(":").Trim()[1]
            SOURCE_IP="BRAK"
        }
    }
    elseif ($_.ID -eq 24)
    {
        [PSCustomObject]@{
            COMPUTER = $($_.MachineName)
            EVENT_TIME = $($_.TimeCreated)
            MESSAGE ="SESJA ZOSTALA ROZLACZONA"
            USER = ($message[2]).Split(":").Trim()[1]
            SESSION_ID=($message[3]).Split(":").Trim()[1]
            SOURCE_IP=$(($message[4]).Split(":").Trim()[1])
        }
    }
    elseif ($_.ID -eq 25)
    {
        [PSCustomObject]@{
            COMPUTER = $($_.MachineName)
            EVENT_TIME = $($_.TimeCreated)
            MESSAGE ="PONOWNE NAWIAZANIE POLACZENIA POWIODLO SIE"
            USER = ($message[2]).Split(":").Trim()[1]
            SESSION_ID=($message[3]).Split(":").Trim()[1]
            SOURCE_IP=$(($message[4]).Split(":").Trim()[1])
        }
    }
    elseif ($_.ID -eq 34)
    {
        [PSCustomObject]@{
            COMPUTER = $($_.MachineName)
            EVENT_TIME = $($_.TimeCreated)
            MESSAGE ="INSTALACJA. PROBA POLACZENIA RDP NIEUDANA"
            USER = "BRAK"
            SESSION_ID="BRAK"
            SOURCE_IP="BRAK"
        }
    }
    elseif ($_.ID -eq 39)
    {
        [PSCustomObject]@{
            COMPUTER = $($_.MachineName)
            EVENT_TIME = $($_.TimeCreated)
            MESSAGE ="SESJA ZOSTALA ROZLACZONA"
            USER = "BRAK"
            SESSION_ID="BRAK"
            SOURCE_IP="BRAK"
        }
    }
    elseif($_.ID -eq 40)
    {

    $hashtable=[ordered]@{
        "0"="BRAK DODATKOWYCH INFORMACJI"
        "1"="APLIKACJA ROZPOCZELA ROZLACZENIE UZYTKOWNIKA"
        "2"="APLIKACJA WYLOGOWALA UZYTKOWNIKA"
        "3"="SERVER ROZLACZYL UZYTKOWNIKA, PONIEWAZ BYL NIEAKTYWNY PRZEZ CZAS DLUZSZY NIZ OKRESLONY W POLITYKACH GPO"
        "4"="SERVER ROZLACZYL UZYTKOWNIKA, PONIEWAZ UZYTKOWNIKA PRZEKROCZYL OKRES PRZEZNACZONY NA POLACZENIE"
        "5"="POLACZENIE UZYTKOWNIKA ZOSTALO ZASTAPIONE PRZEZ INNE POLACZENIE"
        "6"="BRAK WYMAGANEJ PAMIECI BY UTWORZYC POLACZENIE"
        "7"="SERWER ODMOWIL POLACZENIA"
        "8"="SERWER ODMOWIL POLACZENIA Z POWODU BEZPIECZENSTWA"
        "9"="SERWER ODMOWIL POLACZENIA Z POWODU BEZPIECZENSTWA"
        "10"="POTRZEBA ODSWIEZENIA POSWIADCZEN"
        "11"="AKTYWNOSC UZYTKOWNIKA SPOWODOWALA ROZLACZENIE"
        "12"="UZYTKOWNIK WYLOGOWAL SIE, ROZLACZAJAC POLACZENIE"
    }

        [PSCustomObject]@{
            COMPUTER = $($_.MachineName)
            EVENT_TIME = $($_.TimeCreated)
            MESSAGE = $($hashtable[$(($message[0]).Split(":").Trim()[1])])
            USER = "BRAK"
            SESSION_ID="BRAK"
            SOURCE_IP="BRAK"
        }
    }
    elseif ( $_.ID -eq 41) {
        [PSCustomObject]@{
            COMPUTER = $($_.MachineName)
            EVENT_TIME = $($_.TimeCreated)
            MESSAGE ="ROZPOCZECIE ROZSTRZYGANIA SESJI"
            USER = ($message[2]).Split(":").Trim()[1]
            SESSION_ID=($message[3]).Split(":").Trim()[1]
            SOURCE_IP="BRAK"
        }
    }
    elseif ( $_.ID -eq 42) {
        [PSCustomObject]@{
            COMPUTER = $($_.MachineName)
            EVENT_TIME = $($_.TimeCreated)
            MESSAGE ="ROZPOCZECIE ROZSTRZYGANIA SESJI"
            USER = ($message[2]).Split(":").Trim()[1]
            SESSION_ID=($message[3]).Split(":").Trim()[1]
            SOURCE_IP="BRAK"
        }
    }
} | Export-Excel -Path C:\$lam.xlsx 
}

