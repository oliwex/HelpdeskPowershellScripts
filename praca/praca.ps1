###################################
##                              ###
##            secedit           ###
##                              ###
###################################
#region global

$folderName="test"
$path=$env:HOMEDRIVE+"\"+$folderName

#endregion global

#region filenames
#TODO create list


$seceditFile="secedit.cfg"
#endregion filenames

#region paths
#TODO create list

$seceditPath=$path+"\"+$seceditFile
#endregion paths


#region dictionary

$test1=@(
    "EnableAdminAccount",
    "EnableGuestAccount",
    "AdministratorName",
    "GuestName",
    "TakeOwnership",
    "Take ownership of files or other objects",
    "Allow log on through Remote Desktop Services")

$listTest=@{}


#endregion dictionary

#region functions
function Get-SeceditContent([string]$path)
{
    if (!(Test-Path $path))
    {
        New-Item -Path $path 
    }

    secedit /export /cfg $seceditPath
    $seceditContent=Get-Content -Path $seceditPath
    return $seceditContent
}
#endregion functions


#code
Clear-Host

$seceditContent= Get-SeceditContent($path)

$var=($seceditContent | Select-String -Pattern EnableAdminAccount).ToString().Replace(' ','').Split("=")
$listTest.Add($var[0],$var[1])

$listTest

<#

$seceditContent | Select-String -Pattern EnableGuestAccount
$seceditContent | Select-String -Pattern NewAdministratorName
$seceditContent | Select-String -Pattern NewGuestName

$seceditContent | Select-String -Pattern SeTakeOwnershipPrivilege
$seceditContent | Select-String -Pattern SeRemoteInteractiveLogonRight
$seceditContent | Select-String -Pattern DontDisplayLastUserName
$seceditContent | Select-String -Pattern LegalNoticeCaption
$seceditContent | Select-String -Pattern LegalNoticeText

"UAC"
$seceditContent | Select-String -Pattern ConsentPromptBehaviorAdmin
$seceditContent | Select-String -Pattern ConsentPromptBehaviorUser

$seceditContent | Select-String -Pattern ClearPageFileAtShutdown
$seceditContent | Select-String -Pattern ForceUnlockLogon
$seceditContent | Select-String -Pattern CachedLogonsCount
$seceditContent | Select-String -Pattern PasswordExpiryWarning

#>
<#
"Członkowie grupy Użytkownicy pulpitu zdalnego"
(Get-LocalGroupMember "Użytkownicy pulpitu zdalnego").Name

"Członkowie grupy Administratorzy: "
(Get-LocalGroupMember "Administratorzy").Name
#>

#region MESS

#$seceditContent | Select-String -Pattern DontDisplayLastUserName
#$seceditContent | Select-String -Pattern PromptOnSecureDesktop

#endregion MESS
