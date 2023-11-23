function Check-LogonSessions
{
[CmdletBinding()]
    param (
        [Parameter(HelpMessage = "ComputerName to check logon sessions",Position=0,ValueFromPipeline)]
        [Alias("Computer")]
        [string]$computerName
    )
    begin
    {}
    process
    {
        $userFromStationCSV=(quser /server:$computerName 2>&1) -split "\n" -replace '\s{2,}', ','
        if ($userFromStationCSV -match "ID")
        {
            $userObjects=$userFromStationCSV | convertfrom-csv -Delimiter ','
            foreach($userObject in $userObjects)
            {
                if ($($userObject.STATE) -like "Active")
                {
                    [PScustomObject]@{
                        USERNAME=$($userObject.USERNAME)
                        SESSIONNAME=$($userObject.SESSIONNAME)
                        ID=$($userObject.ID)
                        STATE=$($userObject.STATE)
                        IDLE_TIME=$($userObject."IDLE TIME")
                        LOGON_TIME=$($userObject."LOGON TIME")
                    }
                }
                else 
                {
                    [PScustomObject]@{
                        USERNAME=$($userObject.USERNAME)
                        SESSIONNAME="NOT AVAILABLE"
                        ID=$($userObject.SESSIONNAME)
                        STATE=$($userObject.ID)
                        IDLE_TIME=$($userObject.STATE)
                        LOGON_TIME=$($userObject."IDLE TIME")
                    }
                }
            }    
        }
    }
    end
    {}
}
Check-LogonSessions -Computer "computer"