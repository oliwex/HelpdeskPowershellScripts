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

    $data=Get-ADOrganizationalUnit -Filter * -Properties * -SearchBase $oupath -SearchScope 0 | Select-Object -Property * -ExcludeProperty AddedProperties,PropertyNames,RemovedProperties,ModifiedProperties,PropertyCount #ForTesting

    if ($isExtended)
    {
        $data
    }
    else
    {
        $data | Select Name,Description,Street,City,State,PostalCode,Country,ManagedBy
    }
}
function Get-GPOPolicy {
    [CmdletBinding()]
    param(
        [Array] $GroupPolicies,
        [string] $Domain = $Env:USERDNSDOMAIN,
        [string] $Splitter
    )
    if ($null -eq $GroupPolicies) {
        $GroupPolicies = Get-GPO -Domain $Domain -All
    }
    ForEach ($GPO in $GroupPolicies) {
        [xml]$XmlGPReport = $GPO.generatereport('xml')
        #GPO version
        if ($XmlGPReport.GPO.Computer.VersionDirectory -eq 0 -and $XmlGPReport.GPO.Computer.VersionSysvol -eq 0) {
            $ComputerSettings = "NeverModified"
        } else {
            $ComputerSettings = "Modified"
        }
        if ($XmlGPReport.GPO.User.VersionDirectory -eq 0 -and $XmlGPReport.GPO.User.VersionSysvol -eq 0) {
            $UserSettings = "NeverModified"
        } else {
            $UserSettings = "Modified"
        }
        #GPO content
        if ($null -eq $XmlGPReport.GPO.User.ExtensionData) {
            $UserSettingsConfigured = $false
        } else {
            $UserSettingsConfigured = $true
        }
        if ($null -eq $XmlGPReport.GPO.Computer.ExtensionData) {
            $ComputerSettingsConfigured = $false
        } else {
            $ComputerSettingsConfigured = $true
        }
        #Output
        [PsCustomObject] @{
            'Name'                   = $XmlGPReport.GPO.Name
            'Links'                  = $XmlGPReport.GPO.LinksTo | Select-Object -ExpandProperty SOMPath
            'Has Computer Settings'  = $ComputerSettingsConfigured
            'Has User Settings'      = $UserSettingsConfigured
            'User Enabled'           = $XmlGPReport.GPO.User.Enabled
            'Computer Enabled'       = $XmlGPReport.GPO.Computer.Enabled
            'Computer Settings'      = $ComputerSettings
            'User Settings'          = $UserSettings
            'Gpo Status'             = $GPO.GpoStatus
            'Creation Time'          = $GPO.CreationTime
            'Modification Time'      = $GPO.ModificationTime
            'WMI Filter'             = $GPO.WmiFilter.name
            'WMI Filter Description' = $GPO.WmiFilter.Description
            'Path'                   = $GPO.Path
            'GUID'                   = $GPO.Id
            'ACLs'                   = $XmlGPReport.GPO.SecurityDescriptor.Permissions.TrusteePermissions | ForEach-Object -Process {
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

function Get-WinADDomainFineGrainedPolicies {
    [CmdletBinding()]
    param(
        [string] $Domain = $Env:USERDNSDOMAIN
    )
    $FineGrainedPoliciesData = Get-ADFineGrainedPasswordPolicy -Filter * -Server $Domain
    $FineGrainedPolicies = foreach ($Policy in $FineGrainedPoliciesData) {
        [PsCustomObject] @{
            'Name'                          = $Policy.Name
            'Complexity Enabled'            = $Policy.ComplexityEnabled
            'Lockout Duration'              = $Policy.LockoutDuration
            'Lockout Observation Window'    = $Policy.LockoutObservationWindow
            'Lockout Threshold'             = $Policy.LockoutThreshold
            'Max Password Age'              = $Policy.MaxPasswordAge
            'Min Password Length'           = $Policy.MinPasswordLength
            'Min Password Age'              = $Policy.MinPasswordAge
            'Password History Count'        = $Policy.PasswordHistoryCount
            'Reversible Encryption Enabled' = $Policy.ReversibleEncryptionEnabled
            'Precedence'                    = $Policy.Precedence
            'Applies To'                    = $Policy.AppliesTo 
            'Distinguished Name'            = $Policy.DistinguishedName
        }
    }
    return $FineGrainedPolicies

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
    DocNumbering -Text 'Spis jednostek organizacyjnych' -Level 0 -Type Numbered -Heading Heading1 {
        
        DocText {
            "Ta część zawiera spis jednostek organizacyjnych wraz z informacjami o każdej z nich"
        }
        
        $ous=(Get-ADOrganizationalUnit -Filter "*")
        
        foreach($ou in $ous)
        {
            DocNumbering -Text $($ou.Name) -Level 1 -Type Numbered -Heading Heading1 {
            
            $ouInfo=Get-OUsInformation -OU $($ou.DistinguishedName) -Extended:$true

            DocTable -DataTable $ouInfo -Design ColorfulGridAccent5 -AutoFit Window -OverwriteTitle $($ou.DistinguishedName) -Transpose
            
            DocText -LineBreak
            }
        }
       
        DocText -LineBreak
        #TODO: More about OU elements
        #TODO:Definition about every parameter
    }
    #>
    
    #Group Policies
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

        #DocTable -DataTable $ADForest.ForestInformation -Design ColorfulGridAccent5 -AutoFit Window -OverwriteTitle 'Forest Summary'
        DocText -LineBreak
    }

    #FGPP-Fine Grained Password Policies
    DocNumbering -Text 'Fine Grained Password Policies' -Level 0 -Type Numbered -Heading Heading1 {
        
        DocText {
            "Ta część zawiera spis polis grup w każdej jednostce organizacyjnej"
            "Ten blok nie pokazuje informacji o polisach grup, które są podłączone do SITE" #TODO:Get linked gpo to sites
        }

        $fgpps=Get-WinADDomainFineGrainedPolicies

        foreach($fgpp in $fgpps)
        {
            DocNumbering -Text $($fgpp.Name) -Level 1 -Type Numbered -Heading Heading1 {
                DocTable -DataTable $($fgpp | Select-Object -Property * -ExcludeProperty "Applies To") -Design ColorfulGridAccent5 -AutoFit Window -OverwriteTitle $($fgpp.Name) -Transpose
            }
            
            DocNumbering -Text $($fgpp.Name) -Level 2 -Type Bulleted -Heading Heading1 {
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
