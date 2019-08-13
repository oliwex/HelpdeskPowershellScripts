$content=Import-Csv -Path C:\test\ad.csv -Delimiter ";"

$domainName=Get-ADDomain | Select -ExpandProperty forest

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
        $compare=$samAccountName+"@"+$domainName
    
        $upn=$line.("UPN") #bool
        
        if ($upn -eq $compare)
        {
            $upn
        }
        else
        {
            $upn #error here
        }


        $ou=$line.("OU") #bool
        $checkOUInAD=Get-ADOrganizationalUnit -Filter 'Name -like $ou' | Select  -ExpandProperty name
        if($checkOUInAD -eq $ou)
        {
            $ou
        }
        else
        {
            continue
        }
        
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


#New-ADUser -Name "Jack Robinson" -Surname "Robinson" -GivenName "Jack" -DisplayName "Jack Robinson" -CannotChangePassword $true -PasswordNeverExpires $true -SamAccountName "jrobinson" -UserPrincipalName "jrobinson@domena.pl" -Path "OU=Uzytkownicy,DC=domena,DC=local" -AccountPassword(Read-Host -AsSecureString "Input Password") -Enabled $true
