function ConvertTo-Hashtable
{
Param(
        [Parameter(Mandatory=$true)]
        [alias("PsObject")]
        $Object
    )
    $hashtable=@{}
    $Object.psobject.properties | Foreach { $hashtable[$_.Name] = $_.Value }
    $hashtable
}

########################################################
########################################################
########################################################
########################################################
########################################################

function Get-UsersFromOU
{
Param(
        [Parameter(Mandatory=$true)]
        [alias("OU","OrganisationalUnit")]
        [String] $ouPath,
        [alias("Extended")]
        [Switch] $isExtended
    )

    $data=Get-ADUser -Filter * -Properties * -SearchBase $ouPath -SearchScope Onelevel 

    if ($isExtended)
    {
        $data
    }
    else
    {
        $data | Select DistinguishedName,GivenName,Name,ObjectClass,ObjectGuid,SamAccountName,SID,Surname,UserPrincipalName,CannotChangePassword,PasswordNeverExpires,AllowReversiblePasswordEncryption,Enabled,SmartCardLogonRequired,TrustedForDelegation,UseDESKeyOnly,msDS-SupportedEncryptionTypes,userAccountControl
    }
}


function Get-OUsInformation
{
Param(
        [Parameter(Mandatory=$true)]
        [alias("OU","OrganisationalUnit")]
        [String] $oupath,
        [alias("Extended")]
        [Switch] $isExtended
    )

    $data=Get-ADOrganizationalUnit -Filter * -Properties * -SearchBase $oupath

    if ($isExtended)
    {
        $data
    }
    else
    {
        $data | Select Name,Description,Street,City,State,PostalCode,Country,ManagedBy
    }
}


########################################################
########################################################
########################################################
########################################################
########################################################

Documentimo -FilePath "C:\reporty\Starter-AD.docx" {
    DocTOC -Title 'Table of content'

    DocPageBreak
    
    DocText {
        "Jest to dokumentacja domeny ActiveDirectory przeprowadzona w domena.local. Wszytskie informacje są tajne"
    }

    #OU
    DocNumbering -Text 'Spis jednostek organizacyjnych' -Level 0 -Type Numbered -Heading Heading1 {
        
        DocText {
            "Ta część zawiera spis jednostek organizacyjnych wraz z informacjami o każdej z nich"
        }
        
        #DocTable -DataTable $ADForest.ForestInformation -Design ColorfulGridAccent5 -AutoFit Window -OverwriteTitle 'Forest Summary'
        DocText -LineBreak
    }
    
    #Grupy
    DocNumbering -Text 'Spis grup' -Level 0 -Type Numbered -Heading Heading1 {
        
        DocText {
            "Ta część zawiera spis grup w każdej jednostce organizacyjnej"
        }
        #DocTable -DataTable $ADForest.ForestInformation -Design ColorfulGridAccent5 -AutoFit Window -OverwriteTitle 'Forest Summary'
        DocText -LineBreak
    }

    #Użytkownicy
    DocNumbering -Text 'Spis użytkowników' -Level 0 -Type Numbered -Heading Heading1 {
        
        DocText {
            "Ta część zawiera spis użytkowników w każdej jednostce organizacyjnej"
        }
    
        $ous=(Get-ADOrganizationalUnit -Filter *).DistinguishedName
        
        foreach($ou in $ous)
        {
            DocNumbering -Text $uo -Level 1 -Type Numbered -Heading Heading1 {
            
            $ouInfo=Get-OUsInformation -OU $ou -Extended:$false

            DocTable -DataTable $ouInfo -Design ColorfulGridAccent5 -AutoFit Window -OverwriteTitle $($ouInfo.Name.ToString()) -Transpose
            DocText -LineBreak

            $usersInfo=(Get-UsersFromOU -OUpath $OU -Extended:$false)
            foreach($user in $usersInfo)
            {
                DocTable -DataTable $user -Design ColorfulGridAccent5 -AutoFit Window -OverwriteTitle $user.Name -Transpose
                DocText -LineBreak
                #po userze
            }
            }
        }
        DocText -LineBreak
    }

    <#
    #Inna część
    DocNumbering -Text 'Spis użytkowników' -Level 0 -Type Numbered -Heading Heading1 {
        
        DocText {
            "Ta część zawiera spis użytkowników w każdej jednostce organizacyjnej"
        }
        #DocTable -DataTable $ADForest.ForestInformation -Design ColorfulGridAccent5 -AutoFit Window -OverwriteTitle 'Forest Summary'
        DocText -LineBreak
    }
    #>
}
