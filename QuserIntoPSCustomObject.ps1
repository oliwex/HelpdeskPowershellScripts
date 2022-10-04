#parse quser command into powershell pscustomobject
function Check-LogonSessions
{
[CmdletBinding()]
    param (
        [Parameter(HelpMessage = "ComputerName to check logon sessions",Position=0,ValueFromPipeline)]
        [Alias("Computers")]
        [string]$computerName
    )
    begin
    {}
    process
    {
        $lama=(quser  /server:$computerName 2>&1) -split "\n" -replace '\s{2,}', ','
        if ($lama -match "ID")
        {
            $lama | convertfrom-csv -Delimiter ','| ForEach-Object {
                if ($($_).STATE -like "Active") 
                {
                    [PScustomObject]@{
                        USERNAME=$($_).USERNAME
                        SESSIONNAME=$($_).SESSIONNAME
                        ID=$($_).ID
                        STATE=$($_).STATE
                        IDLE_TIME=$($_)."IDLE TIME"
                        LOGON_TIME=$($_)."LOGON TIME"
                    }
                }
                else
                {
                    [PScustomObject]@{
                        USERNAME=$($_).USERNAME
                        SESSIONNAME="NOT AVAILABLE"
                        ID=$($_).SESSIONNAME
                        STATE=$($_).ID
                        IDLE_TIME=$($_).STATE
                        LOGON_TIME=$($_)."IDLE TIME"
                    }
                }
            }
        }
        else
        {
        "Blad, lub zaden uzytkownik nie jest zalogowany"
        }
    }
    end
    {}
}

Check-LogonSessions -Computers ComputerName