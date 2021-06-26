#############################################
#TODO:Definition about every parameter
#
#############################################

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


function Get-OUInformation
{
Param(
        [Parameter(Mandatory=$true)]
        [alias("OU","OrganisationalUnit")]
        [String] $ouPath,
        [alias("Extended")]
        [Switch] $isExtended
    )

    $data=Get-ADOrganizationalUnit -Filter * -Properties * -SearchBase $ouPath -SearchScope 0 | Select-Object -Property * -ExcludeProperty AddedProperties,PropertyNames,RemovedProperties,ModifiedProperties,PropertyCount #ForTesting

    if ($isExtended)
    {
        $data
    }
    else
    {
        $data | Select Name,Description,Street,City,State,PostalCode,Country,ManagedBy
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

function Get-GPOPolicy 
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
    <#
    #OU
    #DONE
    DocNumbering -Text 'Spis jednostek organizacyjnych' -Level 0 -Type Numbered -Heading Heading1 {
        
        DocText {
            "Ta część zawiera spis jednostek organizacyjnych wraz z informacjami o każdej z nich"
        }
        
        $ous=(Get-ADOrganizationalUnit -Filter "*").DistinguishedName
        
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

        #TODO:Definition about every parameter
    }
    #>
    
    #Group Policies
    #DONE
    
    DocNumbering -Text 'GPO list' -Level 0 -Type Numbered -Heading Heading1 {
        
        DocText {
            "Ta część zawiera spis polis grup w każdej jednostce organizacyjnej"
            "Ten blok nie pokazuje informacji o polisach grup, które są podłączone do SITE" #TODO:Get linked gpo to sites
        }
        $gpoPolicies=Get-GPOPolicy
        foreach($gpoPolicy in $gpoPolicies)
        {
            DocNumbering -Text $($gpoPolicy.Name) -Level 1 -Type Numbered -Heading Heading1 {
                DocTable -DataTable $($gpoPolicy | Select-Object -Property * -ExcludeProperty ACLs) -Design ColorfulGridAccent5 -AutoFit Window -OverwriteTitle $($gpoPolicy.Name) -Transpose
            }
            DocNumbering -Text "'$($gpoPolicy.Name)' Permissions" -Level 2 -Type Bulleted -Heading Heading1 {
                DocTable -DataTable $($gpoPolicy).ACLs -Design ColorfulGridAccent5 -AutoFit Window -OverwriteTitle "Permissions"
            }
        }

        DocText -LineBreak
    }
    #TODO:Wykres polityki przypisane do OU vs nieprzypisane
    #TODO:Wykres przypisywania polityk do OU,domeny, site


    #FGPP-Fine Grained Password Policies
    #DONE
    <#
    DocNumbering -Text 'Fine Grained Password Policies' -Level 0 -Type Numbered -Heading Heading1 {
        
        DocText {
            "Ta część zawiera spis polis grup w każdej jednostce organizacyjnej"
            "Ten blok nie pokazuje informacji o polisach grup, które są podłączone do SITE" #TODO:Get linked gpo to sites
        }
        $fgpps=Get-FineGrainedPolicies
        foreach($fgpp in $fgpps)
        {
            DocNumbering -Text $($fgpp.Name) -Level 1 -Type Numbered -Heading Heading1 {
                DocTable -DataTable $($fgpp | Select-Object -Property * -ExcludeProperty "Applies To") -Design ColorfulGridAccent5 -AutoFit Window -OverwriteTitle $($fgpp.Name) -Transpose
            }
            
            DocNumbering -Text "'$($fgpp.Name)' is applied to" -Level 2 -Type Bulleted -Heading Heading1 {
                DocList -Type Bulleted {
                    foreach ($appl in $($fgpp.'Applies To')) 
                    {
                        DocListItem -Level 1 -Text $appl
                    }
                }
            }
        }
        #DocTable -DataTable $ADForest.ForestInformation -Design ColorfulGridAccent5 -AutoFit Window -OverwriteTitle 'Forest Summary'
        DocText -LineBreak
    }
    #>

    <#
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
            
            
                $usersInfo=(Get-UsersFromOU -OUpath $ou -Extended:$false)
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