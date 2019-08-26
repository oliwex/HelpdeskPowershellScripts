$content=Import-Csv -Path C:\test\ad.csv -Delimiter ";"

$domainName=Get-ADDomain | Select -ExpandProperty Forest
$userContainer=Get-ADDomain | Select -ExpandProperty UsersContainer

$defaultUserContainer=$userContainer.Substring(3,$userContainer.IndexOf(",")-3) 

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
        
        if ($line.("UPN") -eq $line.("SamAccountName")+"@"+$domainName)
        {
            $upn=$line.("UPN")
        }
        else
        {
            "Error in UPN. UPN is set as NULL" >> test.txt
            $upn=""
        }



        $checkOUInAD=Get-ADOrganizationalUnit -Filter { Name -like $line.("OU")} | Select  -ExpandProperty name


        if($checkOUInAD -eq $line.("OU"))
        {
            $folder="OU="+$line.("OU")
        }
        else
        {
            "Error in Organizational Unit. User added into default Container" >> test.txt
            $folder="CN="+$defaultUserContainer
        }


        if ($line.("Enabled") -like "*true*")
        {
            $enabled=$true
        }
        else
        {
            $enabled=$false
        }
        
New-ADUser -Name $name -Surname $surname -GivenName $givenName -DisplayName $displayName -CannotChangePassword $cannotChangePassword -PasswordNeverExpires $passwordNeverExpires -SamAccountName $samAccountName -UserPrincipalName $upn -Path "$folder,DC=domena,DC=local" -AccountPassword(Read-Host -AsSecureString "Input Password") -Enabled $enabled

}
