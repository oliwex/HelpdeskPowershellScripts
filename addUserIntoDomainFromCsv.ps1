$content=Import-Csv -Path C:\test\ad.csv -Delimiter ";"

$domainName=Get-ADDomain | Select -ExpandProperty forest
$defaultUserContainer=(Get-ADDomain | Select -ExpandProperty UsersContainer).Substring(3,$userContainter.IndexOf(",")-3) 

foreach($line in $content)
{
    $name=$line.("name")
    $surname=$line.("surname")
    $givenName=$line.("GivenName")
    $displayName=$line.("DisplayName")

    
        if ($line.("CannotChangePassword")  -like "*true*")
        {
            $cannotChangePassword=$true
        }
        else
        {
            $cannotChangePassword=$false
        }
        

        if ($line.("PasswordNeverExpires")  -like "*true*")
        {
            $passwordNeverExpires=$true
        }
        else
        {
            $passwordNeverExpires=$false
        }

        $samAccountName=$line.("SamAccountName")
    
        $upn=$line.("UPN") #bool
        
        if ($upn -eq $samAccountName+"@"+$domainName)
        {
            $upn
        }
        else
        {
            "Error in UPN. UPN is set as " >> test.txt
            $upn
        }


        $ou=$line.("OU") #bool
        $checkOUInAD=Get-ADOrganizationalUnit -Filter 'Name -like $ou' | Select  -ExpandProperty name
        if($checkOUInAD -eq $line.("OU"))
        {
            $ou
        }
        else
        {
            "Error in Organizational Unit. User added into default Container" >> test.txt
            $ou=$defaultUserContainer
        }
        

        if ($line.("Enabled") -like "*true*")
        {
            $enabled=$true
        }
        else
        {
            $enabled=$false
        }
        
New-ADUser -Name $name -Surname $surname -GivenName $givenName -DisplayName $displayName -CannotChangePassword $true -PasswordNeverExpires $true -SamAccountName $samAccountName -UserPrincipalName $upn -Path "OU=$ou,DC=domena,DC=local" -AccountPassword(Read-Host -AsSecureString "Input Password") -Enabled $true

}
