function Get-LocalGroupFromRemoteComputer()
{
    [CmdletBinding()]
    param (
        [Parameter(HelpMessage = "ComputerName do check group membership",Position=0,ValueFromPipeline)]
        [Alias("Computer")]
        [string]$computerName,
        [Parameter(HelpMessage = "GroupName to check members",Position=1)]
        [Alias("Group")]
        [string]$groupName
    )

    begin{}
    process{
        [PSCustomObject]@{
            COMPUTERNAME = $computerName
            GROUPNAME = $groupName
            MEMBERS = $($([ADSI]"WinNT://$computerName/$groupName").psbase.Invoke('members')) | ForEach-Object { "$(([ADSI]$($_)).Path.Substring(8))" }
        }
    }
    end{}
}


Get-Content -Path "D:\lista_stacji.txt" | Get-LocalGroupFromRemoteComputer -Group "Administratorzy"
