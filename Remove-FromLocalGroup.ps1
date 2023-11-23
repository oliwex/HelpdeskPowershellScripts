function Remove-FromLocalGroup()
{
    [CmdletBinding()]
    param (
        [Parameter(HelpMessage = "ComputerName to remove permission",Position=0,ValueFromPipeline)]
        [Alias("Computer")]
        [string[]]$computerName,
        [Parameter(HelpMessage = "Group to remove permission",Position=1)]
        [Alias("Group")]
        [string]$localGroup,
        [Parameter(HelpMessage = "User to remove permission",Position=2)]
        [Alias("User")]
        [string]$domainUser
    )
    begin{}
    process{
        ([ADSI]"WinNT://$computerName/$localGroup,group").psbase.Invoke("Remove",([ADSI]"WinNT://domain/$domainUser").path) 
    }
    end{}

}

Remove-FromLocalGroup -computerNames computer -localGroup "Administratorzy" -domainUser "user"
