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

    if ($extended)
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
        [String] $OUpath,
        [alias("Extended")]
        [Switch] $isExtended
    )

    $data=Get-ADOrganizationalUnit -Filter * -Properties * -SearchBase $OUpath

    if ($extended)
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
    
        $OUs=(Get-ADOrganizationalUnit -Filter *).DistinguishedName
        
        foreach($OU in $OUs)
        {
            DocNumbering -Text $OU -Level 1 -Type Numbered -Heading Heading1 {
            
            $dataTMP=Get-OUsInformation -OU $OU -Extended:$false

            DocTable -DataTable $dataTMP -Design ColorfulGridAccent5 -AutoFit Window -OverwriteTitle "OU" -Transpose
            DocText -LineBreak

            $UserInfo=(Get-UsersFromOU -OUpath $OU -Extended:$false)
            foreach($User in $UserInfo)
            {
                DocTable -DataTable $User -Design ColorfulGridAccent5 -AutoFit Window -OverwriteTitle $User.Name -Transpose
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
