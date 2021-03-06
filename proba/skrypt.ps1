﻿##########################################################################################
#                                GLOBAL VARIABLES                                        #
##########################################################################################
$basePath="C:\reporty\"
$graphFolders = @{
    GPO = "GPO_Graph\"
    OU   = "OU_Graph\"
    FGPP  = "FGPP_Graph\"
    GROUP = "GROUP_Graph\"
}


##########################################################################################
function Get-OUInformation
{
Param(
        [Parameter(Mandatory=$true)]
        [alias("OU_DN","OrganisationalUnitDistinguishedName")]
        [String] $ouPath
        )

    $data=Get-ADOrganizationalUnit -Filter * -Properties * -SearchBase $ouPath -SearchScope 0 | Select-Object CanonicalName,cn,City,Country,Created,DisplayName,DistinguishedName,gPLink,isCriticalSystemObject,LinkedGroupPolicyObjects,ManagedBy,Modified,Name,ObjectCategory,ObjectClass,ObjectGuid,ou,PostalCode,ProtectedFromAccidentalDeletion,showInAdvancedViewOnly,State,StreetAddress,uSNChanged,uSNCreated,whenChanged,whenCreated


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

function Get-OUACL
{
Param(
        [Parameter(Mandatory=$true)]
        [alias("OU_ACL","OrganisationalUnitAccessControlList")]
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

function Get-GROUPInformation
{
Param(
        [Parameter(Mandatory=$true)]
        [alias("Group_DN","GroupDistinguishedName")]
        [String] $groupPath
        )
$data=Get-ADGroup -Filter * -Properties * -SearchBase $groupPath -SearchScope 0 | Select-Object CanonicalName,cn,Created,Description,DisplayName,DistinguishedName,GroupCategory,GroupScope,groupType,HomePage,instanceType,ManagedBy,member,MemberOf,Members,Modified,Name,ObjectCategory,ObjectClass,ObjectGuid,objectSid,ProtectedFromAccidentalDeletion,SamAccountName,aAMAccountType,uSNChanged,uSNCreated,whenChanged,whenCreated

[PSCustomObject] @{
        'CanonicalName'    = $data.CanonicalName
        'Common Name' = $data.cn
        'Created' = $data.Created
        'Description' = $data.Description
        'DisplayName' = $data.DisplayName
        'DistinguishedName' = $data.DistinguishedName
        'GroupCategory' = $data.GroupCategory
        'GroupScope' = $data.GroupScope
        'groupType' = $data.groupType
        'HomePage' = $data.HomePage
        'instanceType' = $data.instanceType
        'ManagedBy' = $data.ManagedBy
        'member' = $data.member
        'MemberOf' = $data.MemberOf
        'Members' = $data.Members
        'Modified' = $data.Modified
        'Name' = $data.Name
        'ObjectCategory' = $data.ObjectCategory
        'ObjectClass' = $data.ObjectClass
        'ObjectGuid' = $data.ObjectGuid
        'objectSid' = $data.objectSid
        'ProtectedFromAccidentalDeletion' = $data.ProtectedFromAccidentalDeletion
        'SamAccountName' = $data.SamAccountName
        'sAMAccountType' = $data.sAMAccountType
        'uSNChanged' = $data.uSNChanged
        'uSNCreated' = $data.uSNCreated
        'whenChanged' = $data.whenChanged
        'whenCreated' = $data.whenCreated
        }
}


function Get-GPOPolicy #TODO:Analysis
{
Param(
        [Parameter(Mandatory=$true)]
        [alias("GPOObject","GroupPolicyObject")]
        $groupPolicyObjectInformation
        )

        [xml]$xmlGPOReport = $groupPolicyObjectInformation.generatereport('xml')
        #GPO version
        if (($xmlGPOReport.GPO.Computer.VersionDirectory -eq 0) -and ($xmlGPOReport.GPO.Computer.VersionSysvol -eq 0)) 
        {
            $computerSettings = "NeverModified"
        } 
        else 
        {
            $computerSettings = "Modified"
        }
        if (($xmlGPOReport.GPO.User.VersionDirectory -eq 0) -and ($xmlGPOReport.GPO.User.VersionSysvol -eq 0))
        {
            $userSettings = "NeverModified"
        } 
        else 
        {
            $userSettings = "Modified"
        }

        #GPO content
        if ($null -eq $xmlGPOReport.GPO.User.ExtensionData) 
        {
            $userSettingsConfigured = $false
        } 
        else 
        {
            $userSettingsConfigured = $true
        }
        if ($null -eq $xmlGPOReport.GPO.Computer.ExtensionData) 
        {
            $computerSettingsConfigured = $false
        } 
        else 
        {
            $computerSettingsConfigured = $true
        }
        #Output
        [PsCustomObject] @{
            'Name'                   = $xmlGPOReport.GPO.Name
            'Links'                  = $xmlGPOReport.GPO.LinksTo | Select-Object -ExpandProperty SOMPath
            'Has Computer Settings'  = $computerSettingsConfigured
            'Has User Settings'      = $userSettingsConfigured
            'User Enabled'           = $xmlGPOReport.GPO.User.Enabled
            'Computer Enabled'       = $xmlGPOReport.GPO.Computer.Enabled
            'Computer Settings'      = $computerSettings
            'User Settings'          = $userSettings
            'Gpo Status'             = $groupPolicyObjectInformation.GpoStatus
            'Creation Time'          = $groupPolicyObjectInformation.CreationTime
            'Modification Time'      = $groupPolicyObjectInformation.ModificationTime
            'WMI Filter'             = $groupPolicyObjectInformation.WmiFilter.name
            'WMI Filter Description' = $groupPolicyObjectInformation.WmiFilter.Description
            'Path'                   = $groupPolicyObjectInformation.Path
            'GUID'                   = $groupPolicyObjectInformation.Id
        }
    }


#TODO:Analysis
function Get-GPOAcl
{
Param(
        [Parameter(Mandatory=$true)]
        [alias("GPOObject","GroupPolicyObject")]
        $groupPolicyObjectAcl
        )

        [xml]$xmlGPOReport = $groupPolicyObjectAcl.generatereport('xml')

        #Output
        [PsCustomObject] @{
            'Name'                   = $xmlGPOReport.GPO.Name
            'ACLs'                   = $xmlGPOReport.GPO.SecurityDescriptor.Permissions.TrusteePermissions | ForEach-Object -Process {
                New-Object -TypeName PSObject -Property @{
                    'User'            = $_.trustee.name.'#Text'
                    'Permission Type' = $_.type.PermissionType
                    'Inherited'       = $_.Inherited
                    'Permissions'     = $_.Standard.GPOGroupedAccessEnum
            }
        }
    }
}



function Get-GraphImage
{
Param(
    [Parameter(Mandatory=$true)]
    [Alias("GraphRoot")]
    $root, 
    [Alias("GraphLeaf")]
    $leaf, 
    [Alias("BasePathToGraphImage")]
    $pathToImage
    )

    $imagePath=Join-Path -Path $pathToImage -ChildPath "$root.png"
        
    $graphTMP = graph g {
    edge -from $root -To $leaf
    }
    
    
    $vizPath=Join-Path -Path $pathToImage -ChildPath "$root.vz"
    Set-Content -Path $vizPath -Value $graphTMP
    Export-PSGraph -Source $vizPath -Destination $imagePath
    
    #cleaning
    Remove-Item -Path $vizPath


    $imagePath
    
}
function Get-FineGrainedPolicies {

    $fineGrainedPoliciesData = Get-ADFineGrainedPasswordPolicy -Filter * -Server $($Env:USERDNSDOMAIN)
    $fineGrainedPolicies = foreach ($policy in $fineGrainedPoliciesData) {
        [PsCustomObject] @{
            'Name'                          = $policy.Name
            'Complexity Enabled'            = $policy.ComplexityEnabled
            'Lockout Duration'              = $policy.LockoutDuration
            'Lockout Observation Window'    = $policy.LockoutObservationWindow
            'Lockout Threshold'             = $policy.LockoutThreshold
            'Max Password Age'              = $policy.MaxPasswordAge
            'Min Password Length'           = $policy.MinPasswordLength
            'Min Password Age'              = $policy.MinPasswordAge
            'Password History Count'        = $policy.PasswordHistoryCount
            'Reversible Encryption Enabled' = $policy.ReversibleEncryptionEnabled
            'Precedence'                    = $policy.Precedence
            'Applies To'                    = $policy.AppliesTo 
            'Distinguished Name'            = $policy.DistinguishedName
        }
    }
    return $fineGrainedPolicies

}
##########################################################################################
#                                TOOL FUNCTIONS                                          #
##########################################################################################


function Get-ReportFolders
{
    Param(
        [Parameter(Mandatory=$true)]
        [Alias("BasePath")]
        [string]$reportPath,
        [Alias("GraphFoldersHashtable")]
        $graphFolders
        )

    foreach($key in $($graphFolders.Keys))
    {
        $graphPath=Join-Path -Path $reportPath -ChildPath $graphFolders[$key]
        $graphFolders[$key]=$graphPath
        New-Item -Path $graphPath -ItemType Directory
    }
    $graphFolders
}

##########################################################################################
#NOTES
####
#Local security groups - tworzone gdy tworzy się AD
#Get-ADGroup -Filter {GroupType -eq -2147483643} | Select-Object Name | Sort-Object Name
#Get-ADGroup -Filter {GroupType -band 1} -Properties Name,GroupType,GroupScope,GroupCategory | Select-Object Name,GroupType,GroupScope,GroupCategory #created by system/builtin
#Get-ADGroup -Filter {GroupType -band 2} -Properties Name,GroupType,GroupScope,GroupCategory | Select-Object Name,GroupType,GroupScope,GroupCategory #global
#Get-ADGroup -Filter {GroupType -band 4} -Properties Name,GroupType,GroupScope,GroupCategory | Select-Object Name,GroupType,GroupScope,GroupCategory #domain local
#Get-ADGroup -Filter {GroupType -band 8} -Properties Name,GroupType,GroupScope,GroupCategory | Select-Object Name,GroupType,GroupScope,GroupCategory #universal
#Get-ADGroup -Filter {GroupType -band 2147483648} -Properties Name,GroupType,GroupScope,GroupCategory | Select-Object Name,GroupType,GroupScope,GroupCategory #security


#category = security/distribution
#scope=universal/global/domain_local
#builtin=tworzone przy starcie AD

#TODO:graph with group difference



##########################################################################################

$reportGraphFolders=Get-ReportFolders -BasePath $basePath -GraphFoldersHashtable $graphFolders


$reportFilePath=Join-Path -Path $basePath -ChildPath "report.docx"
$reportFile = New-WordDocument $reportFilePath



Add-WordText -WordDocument $reportFile -Text 'Raport z Active Directory' -FontSize 28 -FontFamily 'Calibri Light' -Supress $True
Add-WordPageBreak -WordDocument $reportFile -Supress $true
#######################################################################################################################

Add-WordTOC -WordDocument $reportFile -Title "Spis treści" -Supress $true

Add-WordPageBreak -WordDocument $reportFile -Supress $true

#######################################################################################################################
Add-WordText -WordDocument $reportFile -HeadingType Heading1 -Text 'Spis jednostek organizacyjnych' -Supress $true
Add-WordText -WordDocument $reportFile -Text 'Ta część zawiera spis jednostek organizacyjnych wraz z informacjami o każdej z nich' -Supress $True

$ous=(Get-ADOrganizationalUnit -Filter "*")
foreach($ou in $ous)
{
   
    $ouInformation=Get-OUInformation -OrganisationalUnitDistinguishedName $($ou.DistinguishedName)
    
    Add-WordTocItem -WordDocument $reportFile -ListLevel 0 -ListItemType Bulleted -HeadingType Heading1 -Text $($ou.Name) -Supress $true
    Add-WordTable -WordDocument $reportFile -DataTable $ouInformation -Design ColorfulGridAccent5 -AutoFit Window -OverwriteTitle $($ou.Name) -Transpose -Supress $True
    
    Add-WordTocItem -WordDocument $reportFile -ListLevel 1 -ListItemType Bulleted -HeadingType Heading1 -Text "$($ou.Name) Graph" -Supress $true

    $ouTMP=$(Get-ADOrganizationalUnit -Filter "*" -SearchBase $($ou.DistinguishedName) -SearchScope OneLevel).Name
    if ($ouTMP -eq $null)
    {
        Add-WordText -WordDocument $reportFile -Text "No Leafs" -Supress $true        
    }
    else
    {
        $imagePath=Get-GraphImage -GraphRoot $($ou.Name) -GraphLeaf $ouTMP  -BasePathToGraphImage $($reportGraphFolders.OU)

        Add-WordPicture -WordDocument $reportFile -ImagePath $imagePath -Alignment center -ImageWidth 600 -Supress $True
    }
    


    #ACL
    $ouACL=Get-OUACL -OU $($ou.DistinguishedName)
    Add-WordTocItem -WordDocument $reportFile -ListLevel 1 -ListItemType Bulleted -HeadingType Heading1 -Text "$($ou.Name) Permissions" -Supress $true
    Add-WordTable -WordDocument $reportFile -DataTable $($ouACL | Select-Object -Property * -ExcludeProperty ACLs) -Design ColorfulGridAccent5 -AutoFit Window -OverwriteTitle "OU Options" -Transpose -Supress $true
    Add-WordText -WordDocument $reportFile -Text "" -Supress $true
    
    $($ouACL.ACLs) | ForEach-Object {
        Add-WordTable -WordDocument $reportFile -DataTable $($_) -Design ColorfulGridAccent5 -AutoFit Window -OverwriteTitle "$($($_).IdentityReference) Permissions" -Transpose -Supress $true
        Add-WordText -WordDocument $reportFile -Text "" -Supress $true
    }
}

#TODO:Create chart
#######################################################################################################################
Add-WordText -WordDocument $reportFile -Text 'Spis Grup' -HeadingType Heading1 -Supress $true
Add-WordText -WordDocument $reportFile -Text 'Jest to dokumentacja domeny ActiveDirectory przeprowadzona w domena.local. Wszytskie informacje są tajne' -Supress $True 

$groups=(Get-ADGroup -Filter * -Properties *)

foreach($group in $groups)
{
    $groupInformation=Get-GROUPInformation -GroupDistinguishedName $($group.DistinguishedName)

    Add-WordTocItem -WordDocument $reportFile -ListLevel 0 -ListItemType Bulleted -HeadingType Heading1 -Text "$($group.Name)" -Supress $true
    Add-WordTable -WordDocument $reportFile -DataTable $groupInformation -Design ColorfulGridAccent5 -AutoFit Window -OverwriteTitle $($group.Name) -Transpose -Supress $True
    
    Add-WordTocItem -WordDocument $reportFile -ListLevel 1 -ListItemType Bulleted -HeadingType Heading1 -Text "$($group.Name) Graph" -Supress $true
    

    if ($($groupInformation.Members) -eq $null)
    {
        Add-WordText -WordDocument $reportFile -Text "No Leafs" -Supress $true    
    }
    else
    {
        $groupMembers=$($($groupInformation.Members) -split ',*..=')[1]
        $imagePath=Get-GraphImage -GraphRoot $($groupInformation.Name) -GraphLeaf $groupMembers -pathToImage $($reportGraphFolders.GROUP)
        Add-WordPicture -WordDocument $reportFile -ImagePath $imagePath -Alignment center -ImageWidth 600 -Supress $True
    }
}
$chart=$groups | Group-Object GroupCategory | Select-Object Name,Count
Add-WordTocItem -WordDocument $reportFile -ListLevel 1 -ListItemType Bulleted -HeadingType Heading1 -Text  "Wykresy grup dystrybucyjnych/zabezpieczeń" -Supress $true
Add-WordBarChart -WordDocument $reportFile -ChartName 'Stosunek liczby grup zabezpieczeń do grup dystrybucyjnych'-ChartLegendPosition Bottom -ChartLegendOverlay $false -Names "$($chart[0].Name) - $($chart[0].Count)","$($chart[1].Name) - $($chart[1].Count)" -Values $($chart[0].Count),$($chart[1].Count) -BarDirection Column

$chart=$groups | Group-Object GroupScope | Select-Object Name,Count
Add-WordTocItem -WordDocument $reportFile -ListLevel 1 -ListItemType Bulleted -HeadingType Heading1 -Text  "Wykresy grup lokalnych/globalnych/uniwersalnych" -Supress $true
Add-WordBarChart -WordDocument $reportFile -ChartName 'Stosunek liczby grup lokalnych, globalnych,uniwersalnych'-ChartLegendPosition Bottom -ChartLegendOverlay $false -Names "$($chart[0].Name) - $($chart[0].Count)","$($chart[1].Name) - $($chart[1].Count)","$($chart[2].Name) - $($chart[2].Count)" -Values $($chart[0].Count),$($chart[1].Count),$($chart[2].Count) -BarDirection Column


#TODO:More charts

######################################################################################################################
Add-WordText -WordDocument $reportFile -Text 'Spis Użytkowników' -HeadingType Heading1 -Supress $true
Add-WordText -WordDocument $reportFile -Text 'Ta część zawiera spis użytkowników domeny' -Supress $True 


######################################################################################################################
Add-WordText -WordDocument $reportFile -HeadingType Heading1 -Text 'Spis Polis Grup' -Supress $true
Add-WordText -WordDocument $reportFile -Text 'Tutaj znajduje się opis polis grup. Blok nie pokazuje polis podłączonych do SITE' -Supress $True

$groupPolicyObjects = Get-GPO -Domain $($Env:USERDNSDOMAIN) -All

foreach($gpoPolicyObject in $groupPolicyObjects)
{
    $gpoPolicyObjectInformation=Get-GPOPolicy -GroupPolicyObject $gpoPolicyObject
    

    Add-WordTocItem -WordDocument $reportFile -ListLevel 0 -ListItemType Bulleted -HeadingType Heading1 -Text "$($gpoPolicyObjectInformation.Name) Policy" -Supress $true
    Add-WordTable -WordDocument $reportFile -DataTable $gpoPolicyObjectInformation -Design ColorfulGridAccent5 -AutoFit Window -OverwriteTitle $($gpoPolicyObjectInformation.Name) -Transpose -Supress $true
 
    Add-WordTocItem -WordDocument $reportFile -ListLevel 1 -ListItemType Bulleted -HeadingType Heading1 -Text "$($gpoPolicyObjectInformation.Name) Graph" -Supress $true
    
    
    if ($($gpoPolicyObjectInformation.Links) -eq $null)
    {
        Add-WordText -WordDocument $reportFile -Text "No Leafs" -Supress $true    
    }
    else
    {
        $imagePath=Get-GraphImage -GraphRoot $($gpoPolicyObjectInformation.Name) -GraphLeaf $($gpoPolicyObjectInformation.Links) -pathToImage $($reportGraphFolders.GPO)
        Add-WordPicture -WordDocument $reportFile -ImagePath $imagePath -Alignment center -ImageWidth 600 -Supress $True
    }

    Add-WordTocItem -WordDocument $reportFile -ListLevel 1 -ListItemType Bulleted -HeadingType Heading1 -Text "$($gpoPolicyObjectInformation.Name) Permissions" -Supress $true
    
    #ACL
    $gpoACL=$(Get-GPOAcl -GroupPolicyObject $gpoPolicyObject).ACLs
    $gpoACL | ForEach-Object {
        Add-WordTable -WordDocument $reportFile -DataTable $($_) -Design ColorfulGridAccent5 -AutoFit Window -Supress $true -Transpose
        Add-WordText -WordDocument $reportFile -Text "" -Supress $true

    }
}

##############################################################################################################
Add-WordText -WordDocument $reportFile -HeadingType Heading1 -Text 'Spis Fine Grained Password Policies' -Supress $true
Add-WordText -WordDocument $reportFile -Text 'Tutaj znajduje się opis obiektów Fine Grained Password Policies' -Supress $True

$fgpps=Get-FineGrainedPolicies
foreach($fgpp in $fgpps)
{
    Add-WordTocItem -WordDocument $reportFile -ListLevel 0 -ListItemType Bulleted -HeadingType Heading1 -Text $($fgpp.Name) -Supress $true
    Add-WordTable -WordDocument $reportFile -DataTable $fgpp -Design ColorfulGridAccent5 -AutoFit Window -OverwriteTitle $($fgpp.Name) -Transpose -Supress $true

    Add-WordTocItem -WordDocument $reportFile -ListLevel 1 -ListItemType Bulleted -HeadingType Heading1 -Text "'$($fgpp.Name)' is applied to" -Supress $true
    
    
    if ($($fgpp.'Applies To') -eq $null)
    {
        Add-WordText -WordDocument $reportFile -Text "No Leafs" -Supress $true    
    }
    else
    {
        $fgppApllied=$($($fgpp.'Applies To') -split ',*..=')[1]
        $imagePath=Get-GraphImage -GraphRoot $($fgpp.Name) -GraphLeaf $fgppApllied -pathToImage $reportGraphFolders.FGPP
        Add-WordPicture -WordDocument $reportFile -ImagePath $imagePath -Alignment center -ImageWidth 600 -Supress $True
    }
    

}

##############################################################################################################
Save-WordDocument $reportFile -Supress $true -Language 'en-US' -Verbose #-OpenDocument