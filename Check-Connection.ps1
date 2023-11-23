
function Get-Connection
{
    [CmdletBinding()]
    param (
        [Parameter(HelpMessage = "ComputerName to check connection",Position=0,ValueFromPipeline)]
        [Alias("Computer")]
        [string]$computerName
    )
    begin{}
    process{
        [PSCustomObject]@{
            COMPUTERNAME = $computerName
            CONNECTION = $(Test-Path "\\$computerName\C$")
        }
    }
    end{}
}

Get-Content -Path "D:\lista_stacji.txt" | Get-Connection