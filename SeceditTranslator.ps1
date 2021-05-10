$path="C:\test\secedit.cfg"
secedit /export /cfg $path

$content=Get-Content -Path $path


$arrayTranslate=@{
SeNetworkLogonRight = "Access computer from the network"
SeMachineNetworkPrivilege = "Add workstation to a domain"
SeBackupPrivilege = "Users can backup files and directories"
SeChangeNotifyPrivilege = "Users can navigate to folder without being checked for the traverse Folder permission"
SeSystemtimePrivilege="Change system time"
SeCreatePagefilePrivilege="Create pagefile"
SeDebugPrivilege="Users can debug programs"
SeRemoteShutdownPrivilege="Force shutdown from remote system"
SeAuditPrivilege="Generate security audit"
SeIncreaseQuotaPrivilege="Users can set maximum memory quota for process"
SeIncreaseBasePriorityPrivilege="Users can increase base priority class of a process"
SeLoadDriverPrivilege="Users can dynamically load and unload device drivers"
SeBatchLogonRight="Users can log on as batch job"
SeServiceLogonRight="Users can log on as a service"
SeInteractiveLogonRight="Users can log on locally"
SeSecurityPrivilege="Manage auditing and security log"
SeSystemEnvironmentPrinciple="Modify firmware environment values"
SeProfileSingleProcessPrivilege="Users can vew sample performance of process"
SeSystemProfilePrivilege="Profile system performance"
SeAssignPrimaryTokenPrivilege="Replace a process level token"
SeRestorePrivilege="Restore files and privileges"
SeShutdownPrivilege="Shut down the system"
SeTakeOwnershipPrivilege="Take ownership of files or other objects"
SeUndockPrivilege="Remove computer from docking station"
SeEnableDelegationPrivilege="Enable computer and user accounts to be trusted for delegation"
SeManageVolumePrivilege="Users can take volume maintenance tasks"
SeRemoteInteractiveLogonRight="Allow log on through Remote Desktop Services"
SeImpersonatePrivilege="Check which programs are allowed to impersonate a user and act like a user"
SeCreateGlobalPrivilege="Create global objects"
SeIncreaseWorkingSetPrivilege="Increase a process working set"
SeTimeZonePrivilege="USers can change time zone"
SeCreateSymbolicLinkPrivilege="Create symbolic links"
SeDelegateSessionUserImpersonatePrivilege="Delegate user session impersonation"
}

foreach ($hashTable in $arrayTranslate.Keys)
{

$content=$content -replace $hashTable ,$arrayTranslate[$hashTable]
}

$content

