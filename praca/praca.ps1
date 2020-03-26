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

$policyList=[ordered]@{}


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

function Add-ElementToPolicyList($rawElement)
{
    $richElement=($rawElement).ToString().Replace(' ','').Split("=")
    $policyList.Add($richElement[0],$richElement[1])
}


#endregion functions


#code
Clear-Host

$seceditContent= Get-SeceditContent($path)



Add-ElementToPolicyList($seceditContent | Select-String -Pattern EnableAdminAccount)
Add-ElementToPolicyList($seceditContent | Select-String -Pattern NewAdministratorName)
Add-ElementToPolicyList($seceditContent | Select-String -Pattern NewGuestName)

Add-ElementToPolicyList($seceditContent | Select-String -Pattern SeTakeOwnershipPrivilege)
Add-ElementToPolicyList($seceditContent | Select-String -Pattern SeRemoteInteractiveLogonRight)
Add-ElementToPolicyList($seceditContent | Select-String -Pattern DontDisplayLastUserName)
Add-ElementToPolicyList($seceditContent | Select-String -Pattern LegalNoticeCaption)
Add-ElementToPolicyList($seceditContent | Select-String -Pattern LegalNoticeText)



Add-ElementToPolicyList($seceditContent | Select-String -Pattern ConsentPromptBehaviorAdmin)
Add-ElementToPolicyList($seceditContent | Select-String -Pattern ConsentPromptBehaviorUser)



Add-ElementToPolicyList($seceditContent | Select-String -Pattern ClearPageFileAtShutdown)
Add-ElementToPolicyList($seceditContent | Select-String -Pattern ForceUnlockLogon)
Add-ElementToPolicyList($seceditContent | Select-String -Pattern CachedLogonsCount)
Add-ElementToPolicyList($seceditContent | Select-String -Pattern PasswordExpiryWarning)



$policyList | Format-Table -AutoSize









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
