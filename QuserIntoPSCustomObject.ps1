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
        $userFromStationCSV=(quser  /server:$computerName 2>&1) -split "\n" -replace '\s{2,}', ','
        if ($userFromStationCSV -match "ID")
        {
            $userFromStationPSCustomObjects=($userFromStationCSV | convertfrom-csv -Delimiter ',')
            foreach ($userFromStationPSCustomObject in $userFromStationPSCustomObjects)
            {
                if ($userFromStationPSCustomObject.STATE -like "Active") 
                {
                    [PScustomObject]@{
                        COMPUTERNAME=$computerName
                        USERNAME=$userFromStationPSCustomObject.USERNAME
                        SESSIONNAME=$userFromStationPSCustomObject.SESSIONNAME
                        ID=$userFromStationPSCustomObject.ID
                        STATE=$userFromStationPSCustomObject.STATE
                        IDLE_TIME=$userFromStationPSCustomObject."IDLE TIME"
                        LOGON_TIME=$userFromStationPSCustomObject."LOGON TIME"
                    }
                }
                else
                {
                    [PScustomObject]@{
                        COMPUTERNAME=$computerName
                        USERNAME=$userFromStationPSCustomObject.USERNAME
                        SESSIONNAME="NOT AVAILABLE"
                        ID=$userFromStationPSCustomObject.SESSIONNAME
                        STATE=$userFromStationPSCustomObject.ID
                        IDLE_TIME=$userFromStationPSCustomObject.STATE
                        LOGON_TIME=$userFromStationPSCustomObject."IDLE TIME"
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