function Get-BasicComputerInfo
    {
    $computerInfo=Get-ComputerInfo
    $basic=$computerInfo | Select-Object WindowsEditionId,WindowsInstallationType,WindowsInstallDateFromRegistry,WindowsProductName,WindowsRegisteredOrganization,WindowsRegisteredOwner,WindowsSystemRoot,TimeZone,LogonServer,PowerPlatformRole
    $bios=$computerInfo | Select-Object BiosInstallDate,BiosManufacturer,BiosName,BiosReleaseDate,BiosSeralNumber,BiosStatus,BiosSystemMajorVersion,BiosSystemMinorVersion
    $computerSystem=$computerInfo | Select-Object CsCaption,CsChassisSKUNumber,CsCurrentTimeZone,CsDescription,CsDNSHostName,CsDomain,CsDomainRole,CsManufacturer,CsModel,CsName,CsNumberOfLogicalProcessors,CsNumberOfProcessors,CsPartOfDomain,CsPCSystemType,CsPowerManagementSupported,CsPowerOnPasswordStatus,CsPowerState,CsSystemFamily,CsSystemType,CsThermalState,CsTotalPhysicalMemory,CsPhysicallyInstalledMemory,CsUserName
    $os=$computerInfo | Select-Object OsName,OsType,OsVersion,OsBuildNumber,OsBootDevice,OsSystemDevice,OsSystemDirectory,OsSystemDrive,OsWindowsDirectory,OsCountryCode,OsCurrentTimeZone,OsLastBootUpTime,OsUptime,OsDataExecutionPrevention,OsDataExecutionPrevention32bitApplications,OsDataExecutionPreventionDrivers,OsDataExecutionPreventionSupportPolicy,OsTotalVisibleMemorySize,OsFreePhysicalMemory,OsTotalVirtualMemorySize,OsFreeVirtualMemory,OsInUserVirtualMemory,OsTotalSwapSpaceSize,OsSizeStoredInPagingFiles,OsFreeSpaceInPagingFiles,OsManufacturer,OsMaxNumberOfProcesses,OsOrganization,OsArchitecture,OsLanguage,OsPortableOperatingSystem,OsProductType,OsRegisteredUser
    $hyperV=$computerInfo | Select-Object HyperVisorPresent,HyperVRequirementDataExecutionPreventionAvailable,HyperVRequirementSecondLevelAddressTranslation,HyperVRequirementVirtualizationFirmwareEnabled,HyperVRequirementVMMonitorModeExtensions
    $deviceGuard=$computerInfo | Select-Object DeviceGuardSmartStatus,DeviceGuardRequiredSecurityProperties,DeviceGuardAvailableSecurityProperties,DeviceGuardSecurityServicesConfigured,DeviceGuardSecurityServicesRunning,DeviceGuardCodeIntegrityPolicyEnforcementStatus,DeviceGuardUserModeCodeIntegrityPolicyEnforcementStatus

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
Get-BasicComputerInfo
(Get-BasicComputerInfo).DeviceGuard