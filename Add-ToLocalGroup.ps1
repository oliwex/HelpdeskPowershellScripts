function Add-ToLocalGroup()
{
    [CmdletBinding()]
    param (
        [Parameter(HelpMessage = "ComputerName to add permission",Position=0,ValueFromPipeline)]
        [Alias("Computer")]
        [string[]]$computerName,
        [Parameter(HelpMessage = "Group to add permission",Position=1)]
        [Alias("Group")]
        [string]$localGroup,
        [Parameter(HelpMessage = "User to add permission",Position=2)]
        [Alias("User")]
        [string]$domainUser
    )
    begin{}
    process{
        ([ADSI]"WinNT://$computerName/$localGroup,group").psbase.Invoke("Add",([ADSI]"WinNT://domain/$domainUser").path) 
    }
    end{}         
}
Add-ToLocalGroup -computerNames "computer" -localGroup "U�ytkownicy Pulpitu Zdalnego" -domainUser "user"

