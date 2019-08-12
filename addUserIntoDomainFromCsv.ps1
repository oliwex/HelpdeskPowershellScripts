$content=Import-Csv -Path C:\test\ad.csv -Delimiter ";"

foreach($line in $content)
{
    $name=$line.("name")
    $surname=$line.("surname")
    $givenName=$line.("GivenName")
    $displayName=$line.("DisplayName")

    $cannotChangePassword=$line.("CannotChangePassword") 
        if ($cannotChangePassword -like "*true*")
        {
            $cannotChangePassword=$true
        }
        else
        {
            $cannotChangePassword=$false
        }
        
        $passwordNeverExpires=$line.("PasswordNeverExpires") 
        if ($cannotChangePassword -like "*true*")
        {
            $passwordNeverExpires=$true
        }
        else
        {
            $passwordNeverExpires=$false
        }

        $samAccountName=$line.("SamAccountName")

        $upn=$line.("UPN") #bool
    
        $ou=$line.("OU") #bool

        
        $enabled=$line.("Enabled")
        if ($enabled -like "*true*")
        {
            $enabled=$true
        }
        else
        {
            $enabled=$false
        }
        
New-ADUser -Name $name -Surname $surname -GivenName $givenName -DisplayName $displayName -CannotChangePassword $true -PasswordNeverExpires $true -SamAccountName $samAccountName -UserPrincipalName $upn -Path "OU=$ou,DC=domena,DC=local" -AccountPassword(Read-Host -AsSecureString "Input Password") -Enabled $true

}