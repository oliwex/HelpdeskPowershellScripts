<<<<<<< HEAD:proba/Untitled1.ps1
﻿
function Get-OUInformation
=======
﻿function Get-OUInformation
>>>>>>> master:proba/reportGenerator.ps1
{
Param(
        [Parameter(Mandatory=$true)]
        [alias("OU","OrganisationalUnit")]
        [String] $ouPath,
        [alias("Extended")]
        [Switch] $isExtended
    )

    $data=Get-ADOrganizationalUnit -Filter * -Properties * -SearchBase $ouPath -SearchScope 0 | Select-Object CanonicalName,cn,City,Country,Created,DisplayName,DistinguishedName,gPLink,isCriticalSystemObject,LinkedGroupPolicyObjects,ManagedBy,Modified,Name,ObjectCategory,ObjectClass,ObjectGuid,ou,PostalCode,ProtectedFromAccidentalDeletion,showInAdvancedViewOnly,State,StreetAddress,uSNChanged,uSNCreated,whenChanged,whenCreated
    #ObjectGuid,ou,PostalCode,ProtectedFromAccidentalDeletion,showInAdvancedViewOnly,State,StreetAddress,uSNChanged,uSNCreated,whenChanged,whenCreated

        [PSCustomObject] @{
        'CanonicalName'    = $data.CanonicalName
        'Common Name' = $data.cn
        'City' = $data.City
        'Country' = $data.Country
        'Created' = $data.Created
        'DisplayName' = $data.DisplayName
        'DistinguishedName' = $data.DistinguishedName
        'gPLink' = $data.gPLink
        'isCriticalSystemObject' = $data.isCriticalSystemObject
        'LinkedGroupPolicyObjects' = $data.LinkedGroupPolicyObjects
        'ManagedBy' = $data.ManagedBy
        'Modified' = $data.Modified
        'ObjectCategory' = $data.ObjectCategory
        'ObjectClass' = $data.ObjectClass
        'ObjectGuid' = $data.ObjectGuid
        'OrganizationalUnit' = $data.ou
        'PostalCode' = $data.PostalCode

        }
}
<<<<<<< HEAD:proba/Untitled1.ps1
=======

function Get-OUACL
{
Param(
        [Parameter(Mandatory=$true)]
        [alias("OU","OrganisationalUnit")]
        [String] $ouPath
    )
        $path = "AD:\" + $ouPath
        $acls = (Get-Acl -Path $path).Access | Where-Object {$_.IsInherited -eq $false} | Select-Object ActiveDirectoryRights,InheritanceType,ObjectType,InheritedObjectType,ObjectFlags,IdentityReference,IsInherited,InheritanceFlags,PropagationFlags,AccessControlType

        $info=(Get-ACL -Path $path | Select Owner,Group,'AreAccessRulesProtected','AreAuditRulesProtected','AreAccessRulesCanonical','AreAuditRulesCanonical')
    
        [PSCustomObject] @{
        'DN'    = $ouPath
        'Owner' = $info.Owner
        'Group' = $info.Group
        'Are Access Rules Protected' = $info.'AreAccessRulesProtected'
        'Are AuditRules Protected' = $info.'AreAuditRulesProtected'
        'Are Access Rules Canonical' = $info.'AreAccessRulesCanonical'
        'Are Audit Rules Canonical' = $info.'AreAuditRulesCanonical'
        'ACLs' = $acls
        }
}
>>>>>>> master:proba/reportGenerator.ps1

######################################################

$filePath = "C:\reporty\report.docx"
$reportFile = New-WordDocument $filePath

Add-WordText -WordDocument $reportFile -Text 'Raport z Active Directory' -FontSize 28 -FontFamily 'Calibri Light' -Supress $True
Add-WordPageBreak -WordDocument $reportFile -Supress $true

Add-WordTOC -WordDocument $reportFile -Title 'Spis treści' -HeaderStyle Heading1 -Supress $true
Add-WordPageBreak -WordDocument $reportFile -Supress $true

Add-WordTocItem -WordDocument $reportFile -ListLevel 1 -ListItemType Numbered -HeadingType Heading1 -Text 'Wstęp' -Supress $true
Add-WordText -WordDocument $reportFile -Text 'Jest to dokumentacja domeny ActiveDirectory przeprowadzona w domena.local. Wszytskie informacje są tajne' -Supress $True 

Add-WordTocItem -WordDocument $reportFile -ListLevel 1 -ListItemType Numbered -HeadingType Heading1 -Text 'Spis jednostek organizacyjnych' -Supress $true
Add-WordText -WordDocument $reportFile -Text 'Ta część zawiera spis jednostek organizacyjnych wraz z informacjami o każdej z nich' -Supress $True

$ous=(Get-ADOrganizationalUnit -Filter "*").DistinguishedName
foreach($ou in $ous)
{
    Add-WordTocItem -WordDocument $reportFile -ListLevel 2 -ListItemType Numbered -HeadingType Heading1 -Text "$ou" -Supress $true
    Add-WordTable -WordDocument $reportFile -DataTable $(Get-OUInformation -OU $ou) -Design ColorfulGridAccent5 -AutoFit Window -OverwriteTitle $ou -Transpose -Supress $True
<<<<<<< HEAD:proba/Untitled1.ps1
}
    <#
    #OU
    #DONE
        foreach($ou in $ous)
        {
            DocNumbering -Text $ou -Level 1 -Type Numbered -Heading Heading1 {
            DocTable -DataTable $(Get-OUInformation -OU $ou -Extended:$true) -Design ColorfulGridAccent5 -AutoFit Window -OverwriteTitle $ou -Transpose          
            DocText -LineBreak
                DocNumbering -Text "'$ou' Permission" -Level 2 -Type Bulleted -Heading Heading1 {
                DocTable -DataTable $($(Get-OUACL -OU $ou) | Select-Object -Property * -ExcludeProperty ACLs) -Design ColorfulGridAccent5 -AutoFit Window -OverwriteTitle "OU Options" -Transpose
                DocText -LineBreak
                    $(Get-OUACL -ouPath $ou).ACLs | ForEach-Object {
                    DocTable -DataTable $($_) -Design ColorfulGridAccent5 -AutoFit Window -OverwriteTitle "Permissions" -Transpose
                    DocText -LineBreak
                    }
                DocText -LineBreak
                }
            }
        }
        DocText -LineBreak
=======
    
    
    Add-WordTocItem -WordDocument $reportFile -ListLevel 3 -ListItemType Numbered -HeadingType Heading1 -Text "'$ou' Permissions" -Supress $true
    Add-WordTable -WordDocument $reportFile -DataTable $($(Get-OUACL -OU $ou) | Select-Object -Property * -ExcludeProperty ACLs) -Design ColorfulGridAccent5 -AutoFit Window -OverwriteTitle "OU Options" -Transpose -Supress $true
    Add-WordText -WordDocument $reportFile -Text "" -Supress $true
    
    $(Get-OUACL -ouPath $ou).ACLs | ForEach-Object {
        Add-WordTable -WordDocument $reportFile -DataTable $($_) -Design ColorfulGridAccent5 -AutoFit Window -OverwriteTitle "$($($_).IdentityReference) Permissions" -Transpose -Supress $true
        Add-WordText -WordDocument $reportFile -Text "" -Supress $true
        
>>>>>>> master:proba/reportGenerator.ps1
    }
    
}

Save-WordDocument $reportFile -Supress $true -Language 'en-US' -Verbose #-OpenDocument
