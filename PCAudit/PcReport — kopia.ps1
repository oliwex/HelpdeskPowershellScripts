function Get-BasicComputerInfo
{
    $computerInfo=Get-ComputerInfo | Select-Object * 
    
    #region BIOS

    $basic=$computerInfo | Select-Object Windows*,TimeZone,LogonServer,PowerPlatformRole
    switch($basic.PowerPlatformRole)
    {
        "AppliancePC" { $basic.PowerPlatformRole="$($basic.PowerPlatformRole) - The OEM specified an appliance PC role"}
        "Desktop" { $basic.PowerPlatformRole="$($basic.PowerPlatformRole) - The OEM specified a desktop role"}
        "EnterpriseServer" { $basic.PowerPlatformRole="$($basic.PowerPlatformRole) - The OEM specified an enterprise server role"}
        "MaximumEnumValue" { $basic.PowerPlatformRole="$($basic.PowerPlatformRole) - Max enum value"}
        "Mobile" { $basic.PowerPlatformRole="$($basic.PowerPlatformRole) - The OEM specified a mobile role (for example, a laptop)"}
        "PerformanceServer" { $basic.PowerPlatformRole="$($basic.PowerPlatformRole) - The OEM specified a performance server role"}
        "Slate" { $basic.PowerPlatformRole="$($basic.PowerPlatformRole) - The OEM specified a tablet form factor role"}
        "SOHOServer" { $basic.PowerPlatformRole="$($basic.PowerPlatformRole) - The OEM specified a single office/home office (SOHO) server role"}
        "Unspecified" { $basic.PowerPlatformRole="$($basic.PowerPlatformRole) - UnspecifieThe OEM did not specify a specific role"}
        "Workstation" { $basic.PowerPlatformRole="$($basic.PowerPlatformRole) - The OEM specified a workstation role"}
    }

    $bios=$computerInfo | Select-Object Bios*
    switch($bios.BiosFirmwareType)
    {
        "Bios"{$bios.BiosFirmwareType="$($bios.BiosFirmwareType) - The computer booted in legacy BIOS mode"}
        "Max"{$bios.BiosFirmwareType="$($bios.BiosFirmwareType) - Not implemented"}
        "Uefi"{$bios.BiosFirmwareType="$($bios.BiosFirmwareType) - The computer booted in UEFI mode"}
        "Unknown"{$bios.BiosFirmwareType="$($bios.BiosFirmwareType) - The firmware type is unknown"}
    }
    if ($bios.BiosPrimaryBIOS)
    {
        $bios.BiosPrimaryBIOS="Primary BIOS of computerSystem"
    }
    else 
    {
        $bios.BiosPrimaryBIOS = "Not primary BIOS of computerSystem"    
    }
    if($null -eq $bios.BiosSMBIOSMajorVersion)
    {
        $bios.BiosSMBIOSMajorVersion="SMBIOS Major Version not found"
    }
    if($null -eq $bios.BiosSMBIOSMinorVersion)
    {
        $bios.BiosSMBIOSMinorVersion="SMBIOS Minor Version not found"
    }
    if($bios.BiosSMBIOSPresent -eq $true)
    {
        $bios.BiosSMBIOSPresent="SMBIOS is available on this computer system"
    }
    
    $bios.BiosSoftwareElementState="$($bios.BiosSoftwareElementState) - Software element is $($bios.BiosSoftwareElementState)"

    #endregion BIOS

    #region ComputerSystem

    $computerSystem=$computerInfo | Select-Object Cs*
    
    $computerSystem.CsAdminPasswordStatus="$($computerSystem.CsAdminPasswordStatus) - Hardware security is $($computerSystem.CsAdminPasswordStatus)"

    if ($computerSystem.CsAutomaticManagedPagefile)
    {
        $computerSystem.CsAutomaticManagedPagefile="System manages the pagefile.sys file"
    }
    else
    {
        $computerSystem.CsAutomaticManagedPagefile="System is not managing the pagefile.sys file"
    }

    if ($computerSystem.CsAutomaticResetBootOption)
    {
        $computerSystem.CsAutomaticResetBootOption="Automatic reset boot option is enabled"
    }
    else
    {
        $computerSystem.CsAutomaticResetBootOption="Automatic reset boot option is disabled"
    }

    if ($computerSystem.CsAutomaticResetCapability)
    {
        $computerSystem.CsAutomaticResetCapability="Automatic reset is enabled"
    }
    else
    {
        $computerSystem.CsAutomaticResetCapability="Automatic reset is disabled"
    }
    #
    switch($computerSystem.CsBootOptionOnLimit)
    {
        "DoNotReboot" {$computerSystem.CsBootOptionOnLimit = "$($computerSystem.CsBootOptionOnLimit) - do not reboot"}
        "OperatingSystem" {$computerSystem.CsBootOptionOnLimit = "$($computerSystem.CsBootOptionOnLimit) - Boot into operating system"}
        "SystemUtilities" {$computerSystem.CsBootOptionOnLimit = "$($computerSystem.CsBootOptionOnLimit) - Boot into system utilites"}
    }
    #
    switch($computerSystem.CsBootOptionOnWatchdog)
    {
        "DoNotReboot" {$computerSystem.CsBootOptionOnWatchdog = "$($computerSystem.CsBootOptionOnWatchdog) - do not reboot"}
        "OperatingSystem" {$computerSystem.CsBootOptionOnWatchdog = "$($computerSystem.CsBootOptionOnWatchdog) - Boot into operating system"}
        "SystemUtilities" {$computerSystem.CsBootOptionOnWatchdog = "$($computerSystem.CsBootOptionOnWatchdog) - Boot into system utilites"}
    }

    if ($computerSystem.CsBootROMSupported)
    {
        $computerSystem.CsBootROMSupported = "Boot ROM is supported"
    }
    else
    {
        $computerSystem.CsBootROMSupported = "Boot ROM is not supported"
    }

    if($computerSystem.CsChassisBootupState -like "Other")
    {
        $computerSystem.CsChassisBootupState = "$($computerSystem.CsChassisBootupState) - The element is something other than in documentation" 
    }
    else
    {
        $computerSystem.CsChassisBootupState = "$($computerSystem.CsChassisBootupState) - The element is in $($computerSystem.CsChassisBootupState) state" 
    }
    
    if ($null -ne $computerSystem.CsCurrentTimeZone)
    {
        $calc=$computerSystem.CsCurrentTimeZone / 60
        $computerSystem.CsCurrentTimeZone = "$calc h is from London time"
    }

    if ($computerSystem.CsDaylightInEffect)
    {
        $computerSystem.CsDaylightInEffect = "Daylight saving mode is ON"
    }
    else
    {
        $computerSystem.CsDaylightInEffect = "Daylight saving mode is OFF"
    }

    switch($computerSystem.CsDomainRole)
    {
        "BackupDomainController" {$computerSystem.CsDomainRole = "Computer is Backup Domain Controller"}
        "MemberServer" {$computerSystem.CsDomainRole = "Computer is Member Server of Domain"}
        "MemberWorkstation" {$computerSystem.CsDomainRole = "Computer is Member Workstation of Domain"}
        "PrimaryDomainController" {$computerSystem.CsDomainRole = "Computer is Primary Domain Controller"}
        "StandaloneServer" {$computerSystem.CsDomainRole = "Computer is Standalone Server"}
        "StandaloneWorkstation" {$computerSystem.CsDomainRole = "Computer is Standalone Workstation"}
    }
    switch($computerSystem.CsEnableDaylightSavingsTime)
    {
        "True"{$computerSystem.CsEnableDaylightSavingsTime="Daylight saving time is enabled.System time is change 1 hour forward or backward when daylight saving time is started or ended."}
        "False"{$computerSystem.CsEnableDaylightSavingsTime="Daylight saving time is disabled."}
        ""{$computerSystem.CsEnableDaylightSavingsTime="State of daylight saving time is unknown"}
    }
    
    $computerSystem.CsFrontPanelResetStatus="Hardware security setting for the reset button on front Panel is $($computerSystem.CsFrontPanelResetStatus)"

    $computerSystem.CsKeyboardPasswordStatus="Hardware security setting for keyboard password status is $($computerSystem.CsKeyboardPasswordStatus)"

    if ($computerSystem.CsPauseAfterReset -eq -1)
    {
        $computerSystem.CsPauseAfterReset="Time Delay before reboot is initaited value is unknown"
    }
    else
    {
        $calc=$computerSystem.CsPauseAfterReset/1000
        $computerSystem.CsPauseAfterReset="$calc seconds before reboot is initaited"
    }

    switch($computerSystem.CsPCSystemType)
    {
        "AppliancePC" { $computerSystem.CsPCSystemType="$($computerSystem.CsPCSystemType) - The OEM specified an appliance PC role"}
        "Desktop" { $computerSystem.CsPCSystemType="$($computerSystem.CsPCSystemType) - The OEM specified a desktop role"}
        "EnterpriseServer" { $computerSystem.CsPCSystemType="$($computerSystem.CsPCSystemType) - The OEM specified an enterprise server role"}
        "MaximumEnumValue" { $computerSystem.CsPCSystemType="$($computerSystem.CsPCSystemType) - Max enum value"}
        "Mobile" { $computerSystem.CsPCSystemType="$($computerSystem.CsPCSystemType) - The OEM specified a mobile role (for example, a laptop)"}
        "PerformanceServer" { $computerSystem.CsPCSystemType="$($computerSystem.CsPCSystemType) - The OEM specified a performance server role"}
        "Slate" { $computerSystem.CsPCSystemType="$($computerSystem.CsPCSystemType) - The OEM specified a tablet form factor role"}
        "SOHOServer" { $computerSystem.CsPCSystemType="$($computerSystem.CsPCSystemType) - The OEM specified a single office/home office (SOHO) server role"}
        "Unspecified" { $computerSystem.CsPCSystemType="$($computerSystem.CsPCSystemType) - UnspecifieThe OEM did not specify a specific role"}
        "Workstation" { $computerSystem.CsPCSystemType="$($computerSystem.CsPCSystemType) - The OEM specified a workstation role"}
    }

    switch($computerSystem.CsPCSystemTypeEx)
    {
        "AppliancePC" { $computerSystem.CsPCSystemTypeEx="$($computerSystem.CsPCSystemTypeEx) - The OEM specified an appliance PC role"}
        "Desktop" { $computerSystem.CsPCSystemTypeEx="$($computerSystem.CsPCSystemTypeEx) - The OEM specified a desktop role"}
        "EnterpriseServer" { $computerSystem.CsPCSystemTypeEx="$($computerSystem.CsPCSystemTypeEx) - The OEM specified an enterprise server role"}
        "MaximumEnumValue" { $computerSystem.CsPCSystemTypeEx="$($computerSystem.CsPCSystemTypeEx) - Max enum value"}
        "Mobile" { $computerSystem.CsPCSystemTypeEx="$($computerSystem.CsPCSystemTypeEx) - The OEM specified a mobile role (for example, a laptop)"}
        "PerformanceServer" { $computerSystem.CsPCSystemTypeEx="$($computerSystem.CsPCSystemTypeEx) - The OEM specified a performance server role"}
        "Slate" { $computerSystem.CsPCSystemTypeEx="$($computerSystem.CsPCSystemTypeEx) - The OEM specified a tablet form factor role"}
        "SOHOServer" { $computerSystem.CsPCSystemTypeEx="$($computerSystem.CsPCSystemTypeEx) - The OEM specified a single office/home office (SOHO) server role"}
        "Unspecified" { $computerSystem.CsPCSystemTypeEx="$($computerSystem.CsPCSystemTypeEx) - UnspecifieThe OEM did not specify a specific role"}
        "Workstation" { $computerSystem.CsPCSystemTypeEx="$($computerSystem.CsPCSystemTypeEx) - The OEM specified a workstation role"}
    }
    if ($computerSystem.CsPowerManagementSupported)
    {
        $computerSystem.CsPowerManagementSupported="Device can be power managed. Property does not indicate that power management features are not enabled currently, but it indicates that the device is capable of power management."       
    }
    else
    {
         $computerSystem.CsPowerManagementSupported="Device cannot be power managed."   
    }
    $computerSystem.CsPowerOnPasswordStatus="$($computerSystem.CsPowerOnPasswordStatus) - Hardware security setting for PowerOn Password Status is $($computerSystem.CsPowerOnPasswordStatus)"

    $computerSystem.CsPowerState="$($computerSystem.CsPowerState) - Current power state of computer is  $($computerSystem.CsPowerState)"
    if($computerSystem.CsPowerSupplyState -eq "Other")
    {
        $computerSystem.CsPowerSupplyState="$($computerSystem.CsPowerSupplyState) - Element is in state not provided in documentation"  
    }
    else
    {
        $computerSystem.CsPowerSupplyState="$($computerSystem.CsPowerSupplyState) - Current power supply state is in $($computerSystem.CsPowerSupplyState) state"
    }
    if ($computerSystem.CsResetCapability -eq "Other")
    {
        $computerSystem.CsResetCapability="$($computerSystem.CsResetCapability) - indicates that the computer system can be reset. Capability value is other than provided in documentation."
    }
    else
    {
        $computerSystem.CsResetCapability="$($computerSystem.CsResetCapability) - indicates that the computer system can be reset. Capability is $($computerSystem.CsResetCapability)"
    }
    if ($computerSystem.CsResetCount -eq -1)
    {
        $computerSystem.CsResetCount="The value of automatic reset since last reset is unknown."        
    }
    else
    {
        $computerSystem.CsResetCount="The value of automatic reset since last reset is $($computerSystem.CsResetCount)."
    }
    if ($computerSystem.CsResetLimit -eq -1)
    {
        $computerSystem.CsResetLimit="Number of consecutive times a system reset is attempted. The value is uknonwn."        
    }
    else
    {
        $computerSystem.CsResetLimit="Number of consecutive times a system reset is attempted. The value is $($computerSystem.CsResetLimit)" 
    }

    $computerSystem.CsSystemSKUNumber="$($computerSystem.CsSystemSKUNumber) - identifies computer configuration  for sale. It is product ID or purcharse order number" 

    if($computerSystem.CsThermalState -eq "Other")
    {
        $computerSystem.CsThermalState="$($computerSystem.CsThermalState) - Element is in state other than provided in documentation"    
    }
    else
    {
        $computerSystem.CsThermalState="$($computerSystem.CsThermalState) - Element is in $($computerSystem.CsThermalState) state"
    }
    $computerSystem.CsTotalPhysicalMemory="$($($computerSystem.CsTotalPhysicalMemory)/1GB)GB - it is physically installed memory without memory used by system"
    $computerSystem.CsPhysicallyInstalledMemory="$($($computerSystem.CsPhyicallyInstalledMemory)/1MB) GB"


    switch($computerSystem.CsWakeUpType)
    {
        "ACPowerRestored"{ $computerSystem.CsWakeUpType = "ACPower was restored"}
        "APMTimer"{$computerSystem.CsWakeUpType = "Event is APM timer" }
        "LANRemote"{$computerSystem.CsWakeUpType = "Event is a LAN Remove"}
        "ModemRing"{$computerSystem.CsWakeUpType = "Event is Modem Ring"}
        "Other"{$computerSystem.CsWakeUpType = "An event is other then specified in documentation"}
        "PCIPME"{$computerSystem.CsWakeUpType = "Event is a PCI PME# signal"}
        "PowerSwitch"{$computerSystem.CsWakeUpType = "Event is a power switch"}
        "Unknown" {$computerSystem.CsWakeUpType = "Event type is unknown"}
    }

    #endregion ComputerSystem

    #region OperatingSystem
    $os=$computerInfo | Select-Object Os*

    switch($os.OsOperatingSystemSKU)
    {
        "0" {$os.OsOperatingSystemSKU="The SKU is undefined"}
        "1" {$os.OsOperatingSystemSKU="SKU is Ultimate Edition"}
        "2" {$os.OsOperatingSystemSKU="SKU is Home Basic Edition"}
        "3" {$os.OsOperatingSystemSKU="SKU is Home Premium Edition"}
        "4" {$os.OsOperatingSystemSKU="SKU is Enterprise Edition"}
        "5" {$os.OsOperatingSystemSKU="SKU is Home Basic N Edition"}
        "6" {$os.OsOperatingSystemSKU="SKU is Business Edition"}
        "7" {$os.OsOperatingSystemSKU="SKU is Standard Server Edition"}
        "8" {$os.OsOperatingSystemSKU="SKU is Datacenter Server Edition"}
        "9" {$os.OsOperatingSystemSKU="SKU is Small Business Server Edition"}
        "10" {$os.OsOperatingSystemSKU="SKU is Enterprise Server Edition"}
        "11" {$os.OsOperatingSystemSKU="SKU is Starter Edition"}
        "12" {$os.OsOperatingSystemSKU="SKU is Datacenter Server Core Edition"}
        "13" {$os.OsOperatingSystemSKU="SKU is Standard Server Core Edition"}
        "14" {$os.OsOperatingSystemSKU="SKU is Enterprise Server Core Edition"}
        "15" {$os.OsOperatingSystemSKU="SKU is Enterprise Server IA64 Edition"}
        "16" {$os.OsOperatingSystemSKU="SKU is Business N Edition"}
        "17" {$os.OsOperatingSystemSKU="SKU is Web Server Edition"}
        "18" {$os.OsOperatingSystemSKU="SKU is Cluster Server Edition"}
        "19" {$os.OsOperatingSystemSKU="SKU is Home Server Edition"}
        "20" {$os.OsOperatingSystemSKU="SKU is Storage Express Server Edition"}
        "21" {$os.OsOperatingSystemSKU="SKU is Storage Standard Server Edition"}
        "22" {$os.OsOperatingSystemSKU="SKU is Storage Workgroup Server Edition"}
        "23" {$os.OsOperatingSystemSKU="SKU is Storage Enterprise Server Edition"}
        "24" {$os.OsOperatingSystemSKU="SKU is Server For Small Business Edition"}
        "25" {$os.OsOperatingSystemSKU="SKU is Small Business Server Premium Edition"}
        "27" {$os.OsOperatingSystemSKU="SKU is Windows Enterprise"}
        "28" {$os.OsOperatingSystemSKU="SKU is Windows Ultimate"}
        "29" {$os.OsOperatingSystemSKU="SKU is Web Server (core installation)"}
        "33" {$os.OsOperatingSystemSKU="SKU is Server Foundation"}
        "34" {$os.OsOperatingSystemSKU="SKU is Windows Home Server"}
        "36" {$os.OsOperatingSystemSKU="SKU is Windows Server Standard without Hyper-V"}
        "37" {$os.OsOperatingSystemSKU="SKU is Windows Server Datacenter without Hyper-V (full installation)"}
        "38" {$os.OsOperatingSystemSKU="SKU is Windows Server Enterprise without Hyper-V (full installation)"}
        "39" {$os.OsOperatingSystemSKU="SKU is Windows Server Datacenter without Hyper-V (core installation)"}
        "40" {$os.OsOperatingSystemSKU="SKU is Windows Server Standard without Hyper-V (core installation)"}
        "41" {$os.OsOperatingSystemSKU="SKU is Windows Server Enterprise without Hyper-V (core installation)"}
        "42" {$os.OsOperatingSystemSKU="SKU is Microsoft Hyper-V Server"}
        "43" {$os.OsOperatingSystemSKU="SKU is Storage Server Express (core installation)"}
        "44" {$os.OsOperatingSystemSKU="SKU is Storage Server Standard (core installation)"}
        "45" {$os.OsOperatingSystemSKU="SKU is Storage Server Workgroup (core installation)"}
        "46" {$os.OsOperatingSystemSKU="SKU is Storage Server Enterprise (core installation)"}
        "48" {$os.OsOperatingSystemSKU="SKU is Windows Professional"}
        "50" {$os.OsOperatingSystemSKU="SKU is Windows Server Essentials (Desktop Experience installation)"}
        "63" {$os.OsOperatingSystemSKU="SKU is Small Business Server Premium (core installation)"}
        "64" {$os.OsOperatingSystemSKU="SKU is Windows Server Hyper Core V"}
        "87" {$os.OsOperatingSystemSKU="SKU is Windows Thin PC"}
        "89" {$os.OsOperatingSystemSKU="SKU is Windows Embedded Industry"}
        "97" {$os.OsOperatingSystemSKU="SKU is Windows RT"}
        "101" {$os.OsOperatingSystemSKU="SKU is Windows Home"}
        "103" {$os.OsOperatingSystemSKU="SKU is Windows Professional with Media Center"}
        "104" {$os.OsOperatingSystemSKU="SKU is Windows Mobile"}
        "118" {$os.OsOperatingSystemSKU="SKU is Windows Embedded Handheld"}
        "123" {$os.OsOperatingSystemSKU="SKU is Windows IoT (Internet of Things) Core"}
        "143" {$os.OsOperatingSystemSKU="SKU is Windows Server Datacenter Edition (Nano Server installation)"}
        "144" {$os.OsOperatingSystemSKU="SKU is Windows Server Standard Edition (Nano Server installation)"}
        "147" {$os.OsOperatingSystemSKU="SKU is Windows Server Datacenter Edition (Server Core installation)"}
        "148" {$os.OsOperatingSystemSKU="SKU is Windows Server Standard Edition (Server Core installation)"}
    }
    if ($null -eq $os.OsCSDVersion)
    {
        $os.OsCSDVersion = "No service Pack Installed."
    }
    $os.OsCountryCode="$($os.OsCountryCode) - country code based on international prefixes"

    $os.OsCurrentTimeZone="$($($os.OsCurrentTimeZone)/60) h from London Time"
    
    $os.OsLocaleID="$($os.OsCountryCode) - country code based on international prefixes"
    $os.OsLocale="$($os.OsLocale) - culture name derived from OsLocaleID"
    $os.OsLocale ="$($os.CodeSet) - Code page operating system uses"

    switch($os.OsDataExecutionPreventionSupportPolicy)
    {
        "AlwaysOff"{$os.OsDataExecutionPreventionSupportPolicy="DEP is turned off for all 32-bit applications on the computer with no exceptions"}
        "AlwaysOn"{$os.OsDataExecutionPreventionSupportPolicy="DEP is enabled for all 32-bit applications on the computer"}
        "OptIn"{$os.OsDataExecutionPreventionSupportPolicy="DEP is enabled for a limited number of binaries, the kernel, and all Windows-based services. However, it is off by default for all 32-bit applications. A user or administrator must explicitly choose either the Always On or the Opt Out setting before DEP can be applied to 32-bit applications"}
        "OptOff"{$os.OsDataExecutionPreventionSupportPolicy="DEP is enabled by default for all 32-bit applications. A user or administrator can explicitly remove support for a 32-bit application by adding the application to an exceptions list"}
    }
    if ($os.OsDebug)
    {
        $os.OsDebug = "The computer is debug build"
    }
    else
    {
        $os.OsDebug = "The computer is not debug build"
    }
    if($os.OsDistributed)
    {
        $os.OsDistributed="Computer works as cluster node"
    }
    else
    {
        $os.OsDistributed="Computer works single workstation"
    }

    $os.OsEncryptionLevel = "$($os.OsEncryptionLevel) bit - level of operating system encryption"

    switch($os.OsForegroundApplicationBoost)
    {
        "Maximum"{$os.OsForegroundApplicationBoost="$($os.OsForegroundApplicationBoost) - system boosts the quantum length by 18 for foreground application"}
        "Minimum"{$os.OsForegroundApplicationBoost="$($os.OsForegroundApplicationBoost) - system boosts the quantum length by 12 for foreground application"}
        "None"{$os.OsForegroundApplicationBoost="$($os.OsForegroundApplicationBoost) - system boosts the quantum length by 6 for foreground application"}
    }
    
    $os.OsTotalVisibleMemorySize = "$($($os.OsTotalVisibleMemorySize) / 1GB)GB - Total amount, in kilobytes, of physical memory available to the operating system. This value does not necessarily indicate the true amount of physical memory, but what is reported to the operating system as available to it."
    
    $os.OsFreePhysicalMemory = "$($($os.OsFreePhysicalMemory) / 1GB)GB - Number, in kilobytes, of physical memory currently unused and available."
    
    $os.OsTotalVirtualMemorySize = "$($($os.OsTotalVirtualMemorySize) / 1GB)GB - Number, in kilobytes, of virtual memory. For example, this may be calculated by adding the amount of total RAM to the amount of paging space, that is, adding the amount of memory in or aggregated by the computer system to the property, SizeStoredInPagingFiles."

    $os.OsFreeVirtualMemory = "$($($os.OsFreeVirtualMemorySize) / 1GB)GB - Number, in kilobytes, of virtual memory currently unused and available."

    $os.OsInUseVirtualMemory = "$($($os.OsInUseVirtualMemory) / 1GB)GB"

    if($null -ne $os.OsTotalSwapSpaceSize)
    {
        $os.OsTotalSwapSpaceSize = "$($($os.OsTotalSwapSpaceSize) / 1GB)GB - total swap size"
    }
    else 
    {
        $os.OsTotalSwapSpaceSize = "The swap space is not distinguished from page files."
    }
    
    if ($os.OsSizeStoredInPagingFiles -eq 0)
    {
        $os.OsSizeStoredInPagingFiles = "There are no paging files"
    }
    else 
    {
        $os.OsSizeStoredInPagingFiles = "$($os.OsSizeStoredInPagingFiles) KB paging file"
    }

    $os.OsFreeSpaceInPagingFiles = "$($os.OsFreeSpaceInPagingFiles) KB - Number, in kilobytes, that can be mapped into the operating system paging files without causing any other pages to be swapped out"
    
    $os.OsPagingFiles = "$($os.OsPagingFiles) - array of field paths to the operating system paging files"
    
    $os.OsHardwareAbstractionLayer = " $($os.OsHardwareAbstractionLayer) - version of the operating system's Hardware Abstraction Layer (HAL)"
    
    $os.OsMaxNumberOfProcesses = "$($os.OsMaxNumberOfProcesses) maximum number of process contexts the operating system can support"
    
    $os.OsMaxProcessMemorySize = "$($os.OsMaxProcessMemorySize) maximum number of kilobytes of memory that can be allocated to a process"
    
    $os.OsMuiLanguages = "$($os.OsMuiLanguages) array of languages installed on computer"
    
    $os.OsNumberOfProcesses = "$($os.OsNumberOfProcesses) - Number of process contexts currently loaded or running on the operating system"
    
    $os.OsNumberOfUsers = "$($os.OsNumberOfUsers) - Number of user sessions for which the operating system is storing state information currently"
    
    #$os.OsProductSuites #TODO: Returning Array. Table in Table?

    #endregion OperatingSystem
    
    #region HyperV
    $hyperV=$computerInfo | Select-Object HyperV*

    if($hyperV.HyperVisorPresent)
    {
        $hyperV.HyperVisorPresent = "HyperVisor is detected"
    }
    else 
    {
        $hyperV.HyperVisorPresent = "HyperVisor is  not detected"
        
    }
    if ($hyperV.HyperVRequirementDataExecutionPreventionAvailable)
        {
            $hyperV.HyperVRequirementDataExecutionPreventionAvailable = "Data Execution Prevention is available"
        }
        else 
        {
            $hyperV.HyperVRequirementDataExecutionPreventionAvailable = "Data Execution Prevention is not available or unknown"
        }
        
        if ($hyperV.HyperVRequirementSecondLevelAddressTranslation) 
        {
            $hyperV.HyperVRequirementSecondLevelAddressTranslation = "Second Level Address Translation is available"
        }
        else 
        {
            $hyperV.HyperVRequirementSecondLevelAddressTranslation = "Second Level Address Translation is not available or unknown"
        }
        
        if ($hyperV.HyperVRequirementVirtualizationFirmwareEnabled) {
            $hyperV.HyperVRequirementVirtualizationFirmwareEnabled = "Virtualization is enabled by firmware"
        }
        else {
            $hyperV.HyperVRequirementVirtualizationFirmwareEnabled = "Virtualization is not enabled by firmware or is unknown"
        }

        if ($hyperV.HyperVRequirementVMMonitorModeExtensions) {
            $hyperV.HyperVRequirementVMMonitorModeExtensions = "The processor supports Intel or AMD Virtual Machine Monitor extensions"
        }
        else {
            $hyperV.HyperVRequirementVMMonitorModeExtensions = "The processor not supports Intel or AMD Virtual Machine Monitor extensions or the state is unknown"
        }
    #endregion HyperV

    
    $deviceGuard=$computerInfo | Select-Object DeviceGuard*

    $basicInformation = [PSCustomObject]@{
        BasicInformation = $basic
        Bios             = $bios
        ComputerSystem   = $computerSystem
        OperatingSystem  = $os
        HyperV           = $hyperV
        DeviceGuard      = $deviceGuard
    }
    $basicInformation
}
function Get-HardwareInfo
{
    $hardwareInformation = [PSCustomObject]@{
        Controller1394 = Get-1394Controller
        BaseBoard = Get-BaseBoard
        Battery = Get-Battery
        Bios             = Get-BIOS
        Bus = Get-Bus
        CacheMemory = Get-CacheMemory
        CDROM = Get-CDROMDrive
        CompactDisc = Get-CompactDisc
        Desktop = Get-Desktop
        DesktopMonitor = Get-DesktopMonitor
        DiskDrive = Get-DiskDrive
        DiskPartition = Get-DiskPartition
        Fan=Get-Fan
        Glide = Get-GlidePoint
        HeatPipe = Get-HeatPipe
        IDE=Get-IDEController
        InfraredDevice=Get-InfraredDevice
        Keyboard = Get-Keyboard
        LocalDisk=Get-LocalDisk
        LogicalDisk=Get-LogicalDisk
        MemoryArray=Get-MemoryArray
        MemoryDevice=Get-MemoryDevice
        MotherBoardDevice=Get-MotherboardDevice
        Mouse=Get-Mouse
        NetworkAdapter=Get-NetworkAdapterSysInfo
        NetworkAdapterConfiguration=Get-NetworkAdapterConfiguration
        NetworkDrive=Get-NetworkDrive
        OperatingSystem=Get-OperatingSystem
        OpticalSensor=Get-OpticalSensor
        PhysicalMemory=Get-PhysicalMemory
        PhysicalMemoryArray=Get-PhysicalMemoryArray
        PointingDevice=Get-PointingDevice
        PortableBattery=Get-PortableBattery
        PrinterConfiguration=Get-PrinterConfiguration
        Processor=Get-Processor
        RAMDisk=Get-RAMDisk
        Refrigeration=Get-Refrigeration
        RemovableDisk=Get-RemovableDisk
        SCSIController=Get-SCSIControllerSysInfo
        SoundDevice=Get-SoundDevice
        SystemEnclousure=Get-SystemEnclosure
        TapeDrive=Get-TapeDrive
        TemperatureProbe=Get-TemperatureProbe
        TouchPad=Get-TouchPad
        TouchScreen=Get-TouchScreen
        TrackBall=Get-TrackBall
        TrackPoint=Get-TrackPoint
        USBController=Get-USBController
        VideoController=Get-VideoController
        VoltageProbe=Get-VoltageProbe
    }
    $hardwareInformation
}
function Get-MotherBoard
{
Get-CimInstance Win32_BaseBoard | Select-Object * -ExcludeProperty CreationClassNAme,PSComputerName,Cim*

}


function New-HTMLTable()
{
    [CmdletBinding()]
    param (
    [Parameter(HelpMessage="Table content,Position=0")]
    [Alias("TableContent","TC")]
    $content
    )

    $output="<table><tr><td>KEY</td><td>VALUE</td></tr>"
    $content.PSObject.Properties | ForEach-Object { 
        $output += "<tr><td>$($_.Name)</td><td>$($_.Value)</td></tr>"
    }
    $output += "</table>"
    return $output
}


$HTMLBody1 = New-HTMLTable -TableContent $($(Get-BasicComputerInfo).BasicInformation)
$HTMLBody2 = New-HTMLTable -TableContent $($(Get-BasicComputerInfo).Bios)
$HTMLBody3 = New-HTMLTable -TableContent $($(Get-BasicComputerInfo).ComputerSystem)
$HTMLBody4 = New-HTMLTable -TableContent $($(Get-BasicComputerInfo).OperatingSystem)
$HTMLBody5 = New-HTMLTable -TableContent $($(Get-BasicComputerInfo).HyperV)
$HTMLBody6 = New-HTMLTable -TableContent $($(Get-BasicComputerInfo).DeviceGuard)

$HTMLBody7 = New-HTMLTable -TableContent $(Get-MotherBoard)
############################################################################################################
function New-JSScript()
{
$script=@"
    <script>
    function changeContent(content) 
    {
        document.getElementById('lama').innerHTML = content;
    }
    function myAccFunc() 
    {
        var x = document.getElementById("demoAcc");
        if (x.className.indexOf("w3-show") == -1) 
        {
            x.className += " w3-show";
            x.previousElementSibling.className += " w3-green";
        } 
        else 
        {
            x.className = x.className.replace(" w3-show", "");
            x.previousElementSibling.className =
            x.previousElementSibling.className.replace(" w3-green", "");
        }
    }
        </script>
"@
return $script
}

function New-HTMLHead()
{
$head=@"
    <head>
        <title>W3.CSS</title>
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <link rel="stylesheet" href="https://www.w3schools.com/w3css/4/w3.css">
        <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/4.7.0/css/font-awesome.min.css">
    </head>
"@
return $head
}


function New-HTMLBody()
{
$report=@"
<!DOCTYPE html>
<html>
$(New-HTMLHead)
<body>
    <div class="w3-sidebar w3-bar-block w3-light-grey w3-card" style="width:160px;">
        <a href="#" class="w3-bar-item w3-button">Link 1</a>
        
        <div class="w3-bar-item w3-button" onclick="myAccFunc()">
            Accordion <i class="fa fa-caret-down"></i>
        </div>
        
        <div id="demoAcc" class="w3-hide w3-white w3-card-4">
            <a class="w3-bar-item w3-button" onclick="changeContent('$HTMLBody1')">BasicInformation</a>
            <a class="w3-bar-item w3-button" onclick="changeContent('$HTMLBody2')">Bios</a>
            <a class="w3-bar-item w3-button" onclick="changeContent('$HTMLBody3')">ComputerSystem</a>
            <a class="w3-bar-item w3-button" onclick="changeContent('$HTMLBody4')">OperatingSystem</a>
            <a class="w3-bar-item w3-button" onclick="changeContent('$HTMLBody5')">HyperV</a>
            <a class="w3-bar-item w3-button" onclick="changeContent('$HTMLBody6')">DeviceGuard</a>
        </div>
        
        <a class="w3-bar-item w3-button" onclick="changeContent('$HTMLBody7')">MotherBoard</a>
        
        <a class="w3-bar-item w3-button" >Link 3</a>
        
    </div>
    
    <div class="w3-container" id="lama" style="margin-left:160px">
    adsdsa
    </div>
$(New-JSScript)
</body>
</html>
"@

return $report
}
New-HTMLBody | Out-File "test.html"