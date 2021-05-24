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

function Get-UserFromOU
{
Param(
        [Parameter(Mandatory=$true)]
        [alias("OU","OrganisationalUnit")]
        [String] $OUpath,
        [Switch] $extended
    )

    $data=Get-ADUser -Filter * -SearchBase $OUpath -SearchScope Onelevel -Properties *

    if ($extended)
    {
        $data
    }
    else
    {
        $data | Select DistinguishedName,GivenName,Name,ObjectClass,ObjectGuid,SamAccountName,SID,Surname,UserPrincipalName,CannotChangePassword,PasswordNeverExpires,AllowReversiblePasswordEncryption,Enabled,SmartCardLogonRequired,TrustedForDelegation,UseDESKeyOnly,msDS-SupportedEncryptionTypes,userAccountControl
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
     
            $UserInfo=(Get-UserFromOU -OUpath $OU -extended:$false)
                foreach($User in $UserInfo)
                {
                    $hashtable=ConvertTo-Hashtable -Object $User
                    DocTable -DataTable $hashtable -Design ColorfulGridAccent5 -AutoFit Window -OverwriteTitle $User.Name
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
