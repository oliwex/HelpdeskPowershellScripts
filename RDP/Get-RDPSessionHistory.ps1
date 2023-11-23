function Get-RDPSessionHistory {
    [CmdletBinding()]
    param (
        [Parameter(HelpMessage = "ComputerName to check LogonRemoteSesion",Position=0,ValueFromPipeline)]
        [Alias("Computer")]
        $computerName,
        [Parameter(HelpMessage = "Date from which RDP session is checked",Position=1,ValueFromPipeline)]
        [Alias("StartDate")]
        $date1,
        [Parameter(HelpMessage = "Date to which RDP session is checked",Position=2,ValueFromPipeline)]
        [Alias("EndDate")]
        $date2
    )
    process {
        Get-WinEvent -LogName 'Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational' -ComputerName $computerName | Where-Object {($_.ID -eq 1149) -and ($_.TimeCreated -le ($date2)) -and ($_.TimeCreated -ge ($date1))} | Select-Object MachineName,TimeCreated,Message | ForEach-Object {
            $message=$($_.Message).Split("`n")
            [PSCustomObject]@{
                DESTINATION = $($_.MachineName)
                TIME=$($_.TimeCreated)
                USER=($message[2]).Split(":").Trim()[1]
                SOURCE_IP=([System.Net.Dns]::GetHostEntry($(($message[4]).Split(":").Trim()[1]))).HostName
            }
        }
    }
}


Get-RDPSessionHistory -computerName Computer -StartDate '2023-10-01' -EndDate '2023-10-09'


