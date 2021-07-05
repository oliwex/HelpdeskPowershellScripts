

function Get-OUInformation
{
Param(
        [Parameter(Mandatory=$true)]
        [alias("OU","OrganisationalUnit")]
        [String] $ouPath,
        [alias("Extended")]
        [Switch] $isExtended
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

function Get-GPOPolicy #TODO:Analysis
{
    $groupPolicies = Get-GPO -Domain $($Env:USERDNSDOMAIN) -All

    foreach ($gpo in $groupPolicies) 
    {
        [xml]$xmlGPOReport = $gpo.generatereport('xml')
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
            'Gpo Status'             = $gpo.GpoStatus
            'Creation Time'          = $gpo.CreationTime
            'Modification Time'      = $gpo.ModificationTime
            'WMI Filter'             = $gpo.WmiFilter.name
            'WMI Filter Description' = $gpo.WmiFilter.Description
            'Path'                   = $gpo.Path
            'GUID'                   = $gpo.Id
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
}

######################################################

$filePath = "C:\reporty\report.docx"
$reportFile = New-WordDocument $filePath



Add-WordText -WordDocument $reportFile -Text 'Raport z Active Directory' -FontSize 28 -FontFamily 'Calibri Light' -Supress $True
Add-WordPageBreak -WordDocument $reportFile -Supress $true

Add-WordTOC -WordDocument $reportFile -Title "Spis treści" -Supress $true

Add-WordPageBreak -WordDocument $reportFile -Supress $true


Add-WordText -WordDocument $reportFile -Text 'Wstęp' -HeadingType Heading1 -Supress $true
Add-WordText -WordDocument $reportFile -Text 'Jest to dokumentacja domeny ActiveDirectory przeprowadzona w domena.local. Wszytskie informacje są tajne' -Supress $True 



Add-WordText -WordDocument $reportFile -HeadingType Heading1 -Text 'Spis jednostek organizacyjnych' -Supress $true
Add-WordText -WordDocument $reportFile -Text 'Ta część zawiera spis jednostek organizacyjnych wraz z informacjami o każdej z nich' -Supress $True

$ous=(Get-ADOrganizationalUnit -Filter "*")
foreach($ou in $ous)
{
    Add-WordTocItem -WordDocument $reportFile -ListLevel 0 -ListItemType Bulleted -HeadingType Heading1 -Text "$($ou.Name)" -Supress $true
    Add-WordTable -WordDocument $reportFile -DataTable $(Get-OUInformation -OU $($ou.DistinguishedName)) -Design ColorfulGridAccent5 -AutoFit Window -OverwriteTitle $($ou.Name) -Transpose -Supress $True
    
    Add-WordTocItem -WordDocument $reportFile -ListLevel 1 -ListItemType Bulleted -HeadingType Heading1 -Text "'$($ou.Name)' Graph" -Supress $true

        $image="C:\reporty\$($ou.Name).png"
        $graph = graph g {
            edge -from $($ou.Name) -To $($(Get-ADOrganizationalUnit -Filter "*" -SearchBase $ou -SearchScope OneLevel).Name)
            }
        Set-Content -Path "C:\reporty\$($ou.Name).vz" -Value $graph
        Export-PSGraph -Source "C:\reporty\$($ou.Name).vz" -Destination $image
        Add-WordPicture -WordDocument $reportFile -ImagePath $image -Alignment center -ImageWidth 600 -Supress $True
       #TODO: Write text if OU is last


    Add-WordTocItem -WordDocument $reportFile -ListLevel 1 -ListItemType Bulleted -HeadingType Heading1 -Text "'$($ou.Name)' Permissions" -Supress $true
    Add-WordTable -WordDocument $reportFile -DataTable $($(Get-OUACL -OU $($ou.DistinguishedName)) | Select-Object -Property * -ExcludeProperty ACLs) -Design ColorfulGridAccent5 -AutoFit Window -OverwriteTitle "OU Options" -Transpose -Supress $true
    Add-WordText -WordDocument $reportFile -Text "" -Supress $true
    
    $(Get-OUACL -ouPath $($ou.DistinguishedName)).ACLs | ForEach-Object {
        Add-WordTable -WordDocument $reportFile -DataTable $($_) -Design ColorfulGridAccent5 -AutoFit Window -OverwriteTitle "$($($_).IdentityReference) Permissions" -Transpose -Supress $true
        Add-WordText -WordDocument $reportFile -Text "" -Supress $true
        
    }
    
}
###########################################################################################################
Add-WordText -WordDocument $reportFile -HeadingType Heading1 -Text 'Spis Polis Grup' -Supress $true
Add-WordText -WordDocument $reportFile -Text 'Tutaj znajduje się opis polis grup. Blok nie pokazuje polis podłączonych do SITE' -Supress $True

$gpoPolicies=Get-GPOPolicy
$counter=0
foreach($gpoPolicy in $gpoPolicies)
{

    Add-WordTocItem -WordDocument $reportFile -ListLevel 0 -ListItemType Bulleted -HeadingType Heading1 -Text "$($gpoPolicy.Name) Policy" -Supress $true
    Add-WordTable -WordDocument $reportFile -DataTable $($gpoPolicy | Select-Object -Property * -ExcludeProperty ACLs) -Design ColorfulGridAccent5 -AutoFit Window -OverwriteTitle $($gpoPolicy.Name) -Transpose -Supress $true

    Add-WordTocItem -WordDocument $reportFile -ListLevel 1 -ListItemType Bulleted -HeadingType Heading1 -Text "'$($gpoPolicy.Name)' Permissions" -Supress $true
    $($($gpoPolicy).ACLs) | ForEach-Object {
        Add-WordTable -WordDocument $reportFile -DataTable $($_) -Design ColorfulGridAccent5 -AutoFit Window -OverwriteTitle "Permissions" -Supress $true -Transpose
        Add-WordText -WordDocument $reportFile -Text "" -Supress $true
    }
    if ($gpoPolicy.Links -eq $null)
    {
        $counter++
    }
}

Add-WordTocItem -WordDocument $reportFile -ListLevel 0 -ListItemType Numbered -HeadingType Heading1 -Text "Wykres - Polityki przypisane\nieprzypisane" -Supress $true

Add-WordPieChart -WordDocument $reportFile -ChartName 'Polityki przypisane/nieprzypisane' -Names "Polityki nieprzypisane - $counter", "Polityki przypisane - $($($gpoPolicies.Count)-$counter)" -Values $counter,$($($gpoPolicies.Count)-$counter) -ChartLegendPosition Bottom -ChartLegendOverlay $false

Save-WordDocument $reportFile -Supress $true -Language 'en-US' -Verbose #-OpenDocument

