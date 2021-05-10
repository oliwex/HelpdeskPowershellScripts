Function Get-WindowsUpdateConfiguration{
    <#
        .SYNOPSIS
            Get the configuration of the WSUS agent based on registry keys.
        .DESCRIPTION
            This function use OpenRemoteBaseKey from .Net to query remote computer.
        .PARAMETER ComputerName
            Named of the remote computer.
            Defaulted to the local host.
        .EXAMPLE
            Get-WindowsUpdateConfiguration -ComputerName Server1
            Get the WSUS agent configuration from registry.
        .EXAMPLE
            Get-ADForest | Select-Object -ExpandProperty Domains | % {Get-ADComputer -Filter {OperatingSystem -like '*server*'} -Server $_} | Select-Object -ExpandProperty Name | Get-windowsUpdateConfiguration | Export-Csv -NoTypeInformation -Delimiter ';' 'windowsUpdateConfiguration.csv'
            Get all the computers inside the curent forest and get the WSUS agent configuration for all of them. Can be quite long.
        .NOTES
        .LINK
            https://itfordummies.net
        .INPUTS
        .OUTPUTS
    #>
    Param(
        [Parameter(ValueFromPipeline = $true)]
        [String[]]$ComputerName = $env:COMPUTERNAME
    )

    Begin{
        $Hive = [Microsoft.Win32.RegistryHive]::LocalMachine
    }
    Process{
        try{
            if(Test-Connection -ComputerName $ComputerName -Quiet -Count 3 -ErrorAction Stop){

                $reg = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey($Hive, $ComputerName)

                $WindowsUpdateKeyPath   = 'Software\Policies\Microsoft\Windows\WindowsUpdate'
                $AutomaticUpdateKeyPath = 'Software\Policies\Microsoft\Windows\WindowsUpdate\AU'

                try{
                    $WindowsUpdateKey   = $reg.OpenSubKey($WindowsUpdateKeyPath)
                    try{
                        $AcceptTrustedPublisherCerts = $WindowsUpdateKey.GetValue('AcceptTrustedPublisherCerts')
                    }
                    catch{
                        $AcceptTrustedPublisherCerts = $_
                    }
                    try{
                        $DisableWindowsUpdateAccess  = $WindowsUpdateKey.GetValue('DisableWindowsUpdateAccess')
                    }
                    catch{
                        $DisableWindowsUpdateAccess = $_
                    }
                    try{
                        $ElevateNonAdmins            = $WindowsUpdateKey.GetValue('ElevateNonAdmins')
                    }
                    catch{
                        $ElevateNonAdmins = $_
                    }
                    try{
                        $TargetGroup                 = $WindowsUpdateKey.GetValue('TargetGroup')
                    }
                    catch{
                        $TargetGroup = $_
                    }
                    try{
                        $TargetGroupEnabled          = $WindowsUpdateKey.GetValue('TargetGroupEnabled')
                    }
                    catch{
                        $TargetGroupEnabled = $_
                    }
                    try{
                        $WUServer                    = $WindowsUpdateKey.GetValue('WUServer')
                    }
                    catch{
                        $WUServer = $_
                    }
                    try{
                        $WUStatusServer              = $WindowsUpdateKey.GetValue('WUStatusServer')
                    }
                    catch{
                        $WUStatusServer = $_
                    }

                }
                catch{
                    $AcceptTrustedPublisherCerts = "$WindowsUpdateKeyPath : $_"
                    $DisableWindowsUpdateAccess = "$WindowsUpdateKeyPath : $_"
                    $ElevateNonAdmins = "$WindowsUpdateKeyPath : $_"
                    $TargetGroup = "$WindowsUpdateKeyPath : $_"
                    $TargetGroupEnabled = "$WindowsUpdateKeyPath : $_"
                    $WUServer = "$WindowsUpdateKeyPath : $_"
                    $WUStatusServer = "$WindowsUpdateKeyPath : $_"
                }

                try{
                    $AutomaticUpdateKey = $reg.OpenSubKey($AutomaticUpdateKeyPath)
                    try{
                        $AUOptions                     = switch ($AutomaticUpdateKey.GetValue('AUOptions')){
                            '2' {'Notify before download.'}
                            '3' {'Automatically download and notify of installation.'}
                            '4' {'Automatically download and schedule installation. Only valid if values exist for ScheduledInstallDay and ScheduledInstallTime.'}
                            '5' {'Automatic Updates is required and users can configure it.'}
                            Default {$AutomaticUpdateKey.GetValue('AUOptions')}
                        }
                    }
                    catch{$AUOptions = $_}
                    try{
                        $AutoInstallMinorUpdates       = switch ($AutomaticUpdateKey.GetValue('AutoInstallMinorUpdates')){
                            '0' {'Treat minor updates like other updates.'}
                            '1' {'Silently install minor updates.'}
                            Default {$AutomaticUpdateKey.GetValue('AutoInstallMinorUpdates')}
                        }
                    }
                    catch{$AutoInstallMinorUpdates = $_}
                    try{
                        $DetectionFrequency            = $AutomaticUpdateKey.GetValue('DetectionFrequency')
                    }
                    catch{$DetectionFrequency = $_}
                    try{
                        $DetectionFrequencyEnabled     = switch ($AutomaticUpdateKey.GetValue('DetectionFrequencyEnabled')){
                            '0' {'Disable custom detection frequency (use default value of 22 hours).'}
                            '1' {'Enable detection frequency.'}
                            Default {$AutomaticUpdateKey.GetValue('DetectionFrequencyEnabled')}
                        }
                    }
                    catch{$DetectionFrequencyEnabled = $_}
                    try{
                        $NoAutoRebootWithLoggedOnUsers = switch ($AutomaticUpdateKey.GetValue('NoAutoRebootWithLoggedOnUsers')){
                            '0' {'Automatic Updates notifies the user that the computer will restart in 15 minutes.'}
                            '1' {'Logged-on user can decide whether to restart the client computer.'}
                            Default {$AutomaticUpdateKey.GetValue('NoAutoRebootWithLoggedOnUsers')}
                        }
                    }
                    catch{$NoAutoRebootWithLoggedOnUsers = $_}
                    try{
                        $NoAutoUpdate                  = switch ($AutomaticUpdateKey.GetValue('NoAutoUpdate')){
                            '0' {'Enable Automatic Updates.'}
                            '1' {'Disable Automatic Updates.'}
                            Default {$AutomaticUpdateKey.GetValue('NoAutoUpdate')}
                        }
                    }
                    catch{$NoAutoUpdate = $_}
                    try{
                        $RebootRelaunchTimeout         = $AutomaticUpdateKey.GetValue('RebootRelaunchTimeout')
                    }
                    catch{$RebootRelaunchTimeout = $_}
                    try{
                        $RebootRelaunchTimeoutEnabled  = switch ($AutomaticUpdateKey.GetValue('RebootRelaunchTimeoutEnabled')){
                            '0' {'Disable custom RebootRelaunchTimeout(use default value of 10 minutes).'}
                            '1' {'Enable RebootRelaunchTimeout.'}
                            Default {$AutomaticUpdateKey.GetValue('RebootRelaunchTimeoutEnabled')}
                        }
                    }
                    catch{$RebootRelaunchTimeoutEnabled = $_}
                    try{
                        $RebootWarningTimeout          = $AutomaticUpdateKey.GetValue('RebootWarningTimeout')
                    }
                    catch{$RebootWarningTimeout = $_}
                    try{
                        $RebootWarningTimeoutEnabled   = switch ($AutomaticUpdateKey.GetValue('RebootWarningTimeoutEnabled')){
                            '0' {'Disable custom RebootWarningTimeout (use default value of 5 minutes).'}
                            '1' {'Enable RebootWarningTimeout.'}
                            Default {$AutomaticUpdateKey.GetValue('RebootWarningTimeoutEnabled')}
                        }
                    }
                    catch{$RebootWarningTimeoutEnabled = $_}
                    try{
                        $RescheduleWaitTime            = $AutomaticUpdateKey.GetValue('RescheduleWaitTime')
                    }
                    catch{$RescheduleWaitTime = $_}
                    try{
                        $RescheduleWaitTimeEnabled     = switch ($AutomaticUpdateKey.GetValue('RescheduleWaitTimeEnabled')){
                            '0' {'Disable RescheduleWaitTime (attempt the missed installation during the next scheduled installation time).'}
                            '1' {'Enable RescheduleWaitTime .'}
                            Default {$AutomaticUpdateKey.GetValue('RescheduleWaitTimeEnabled')}
                        }
                    }
                    catch{$RescheduleWaitTimeEnabled = $_}
                    try{
                        $ScheduledInstallDay           = switch ($AutomaticUpdateKey.GetValue('ScheduledInstallDay')){
                            '0' {'Every day.'}
                            '1' {'Sunday (Only valid if AUOptions = 4.)'}
                            '2' {'Monday (Only valid if AUOptions = 4.)'}
                            '3' {'Tuesday (Only valid if AUOptions = 4.)'}
                            '4' {'Wenesday (Only valid if AUOptions = 4.)'}
                            '5' {'Thursday (Only valid if AUOptions = 4.)'}
                            '6' {'Friday (Only valid if AUOptions = 4.)'}
                            '7' {'Saturday (Only valid if AUOptions = 4.)'}
                            Default {$AutomaticUpdateKey.GetValue('ScheduledInstallDay')}
                        }
                    }
                    catch{$ScheduledInstallDay = $_}
                    try{
                        $ScheduledInstallTime          = $AutomaticUpdateKey.GetValue('ScheduledInstallTime')
                    }
                    catch{$ScheduledInstallTime = $_}
                    try{
                        $UseWUServer                   = switch ($AutomaticUpdateKey.GetValue('UseWUServer')){
                            '0' {'The computer gets its updates from Microsoft Update. The WUServer value is not respected unless this key is set.'}
                            '1' {'The computer gets its updates from a WSUS server. The WUServer value is not respected unless this key is set.'}
                            Default {$AutomaticUpdateKey.GetValue('UseWUServer')}
                        }
                    }
                    catch{$UseWUServer = $_}
                }
                catch{
                    $AUOptions = "$AutomaticUpdateKeyPath : $_"
                    $AutoInstallMinorUpdates = "$AutomaticUpdateKeyPath : $_"
                    $AUAutoInstallMinorUpdatesOptions = "$AutomaticUpdateKeyPath : $_"
                    $DetectionFrequency = "$AutomaticUpdateKeyPath : $_"
                    $DetectionFrequencyEnabled = "$AutomaticUpdateKeyPath : $_"
                    $NoAutoRebootWithLoggedOnUsers = "$AutomaticUpdateKeyPath : $_"
                    $NoAutoUpdate = "$AutomaticUpdateKeyPath : $_"
                    $RebootRelaunchTimeout = "$AutomaticUpdateKeyPath : $_"
                    $RebootRelaunchTimeoutEnabled = "$AutomaticUpdateKeyPath : $_"
                    $RebootWarningTimeout = "$AutomaticUpdateKeyPath : $_"
                    $RebootWarningTimeoutEnabled = "$AutomaticUpdateKeyPath : $_"
                    $RescheduleWaitTime = "$AutomaticUpdateKeyPath : $_"
                    $RescheduleWaitTimeEnabled = "$AutomaticUpdateKeyPath : $_"
                    $ScheduledInstallDay = "$AutomaticUpdateKeyPath : $_"
                    $ScheduledInstallTime = "$AutomaticUpdateKeyPath : $_"
                    $UseWUServer = "$AutomaticUpdateKeyPath : $_"
                }
            }
            else{
                $AcceptTrustedPublisherCerts = $DisableWindowsUpdateAccess = $ElevateNonAdmins = $TargetGroup = $TargetGroupEnabled = $WUServer = $WUStatusServer = $AUOptions = $AutoInstallMinorUpdates = $AUAutoInstallMinorUpdatesOptions = $DetectionFrequency = $DetectionFrequencyEnabled = $NoAutoRebootWithLoggedOnUsers = $NoAutoUpdate = $RebootRelaunchTimeout = $RebootRelaunchTimeoutEnabled = $RebootWarningTimeout = $RebootWarningTimeoutEnabled = $RescheduleWaitTime = $RescheduleWaitTimeEnabled = $ScheduledInstallDay = $ScheduledInstallTime = $UseWUServer = 'Offline'
            }
        }#end try inside process
        catch{
            Write-Warning -Message "$ComputerName : $_"
            $AcceptTrustedPublisherCerts = $DisableWindowsUpdateAccess = $ElevateNonAdmins = $TargetGroup = $TargetGroupEnabled = $WUServer = $WUStatusServer = $AUOptions = $AutoInstallMinorUpdates = $AUAutoInstallMinorUpdatesOptions = $DetectionFrequency = $DetectionFrequencyEnabled = $NoAutoRebootWithLoggedOnUsers = $NoAutoUpdate = $RebootRelaunchTimeout = $RebootRelaunchTimeoutEnabled = $RebootWarningTimeout = $RebootWarningTimeoutEnabled = $RescheduleWaitTime = $RescheduleWaitTimeEnabled = $ScheduledInstallDay = $ScheduledInstallTime = $UseWUServer = $_
        }
        finally{
            New-Object -TypeName PSObject -Property @{
                ComputerName                = "$ComputerName"
                AcceptTrustedPublisherCerts = $AcceptTrustedPublisherCerts
                DisableWindowsUpdateAccess  = $DisableWindowsUpdateAccess
                ElevateNonAdmins            = $ElevateNonAdmins
                TargetGroup                 = $TargetGroup
                TargetGroupEnabled          = $TargetGroupEnabled
                WUServer                    = $WUServer
                WUStatusServer              = $WUStatusServer

                AUOptions                        = $AUOptions
                AutoInstallMinorUpdates          = $AutoInstallMinorUpdates
                AUAutoInstallMinorUpdatesOptions = $AUAutoInstallMinorUpdatesOptions
                DetectionFrequency               = $DetectionFrequency
                DetectionFrequencyEnabled        = $DetectionFrequencyEnabled
                NoAutoRebootWithLoggedOnUsers    = $NoAutoRebootWithLoggedOnUsers
                NoAutoUpdate                     = $NoAutoUpdate
                RebootRelaunchTimeout            = $RebootRelaunchTimeout
                RebootRelaunchTimeoutEnabled     = $RebootRelaunchTimeoutEnabled
                RebootWarningTimeout             = $RebootWarningTimeout
                RebootWarningTimeoutEnabled      = $RebootWarningTimeoutEnabled
                RescheduleWaitTime               = $RescheduleWaitTime
                RescheduleWaitTimeEnabled        = $RescheduleWaitTimeEnabled
                ScheduledInstallDay              = $ScheduledInstallDay
                ScheduledInstallTime             = $ScheduledInstallTime
                UseWUServer                      = $UseWUServer
            }
            #Reset Variables
            $AcceptTrustedPublisherCerts = $DisableWindowsUpdateAccess = $ElevateNonAdmins = $TargetGroup = $TargetGroupEnabled = $WUServer = $WUStatusServer = $AUOptions = $AutoInstallMinorUpdates = $AUAutoInstallMinorUpdatesOptions = $DetectionFrequency = $DetectionFrequencyEnabled = $NoAutoRebootWithLoggedOnUsers = $NoAutoUpdate = $RebootRelaunchTimeout = $RebootRelaunchTimeoutEnabled = $RebootWarningTimeout = $RebootWarningTimeoutEnabled = $RescheduleWaitTime = $RescheduleWaitTimeEnabled = $ScheduledInstallDay = $ScheduledInstallTime = $UseWUServer = $null
        }
    }#EndProcess
    End{}
}

Get-WindowsUpdateConfiguration
