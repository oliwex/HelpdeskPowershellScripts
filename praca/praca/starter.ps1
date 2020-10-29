##########################FUNCTIONS####################################
function Get-FilesReport
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true,HelpMessage="UserName.",Position=0)]
        [String]$userName,
        [Parameter(Mandatory=$true,HelpMessage="GroupName",Position=1)]
        [String]$groupName,
        [Parameter(Mandatory=$true,HelpMessage="Department",Position=2)]
        [String]$departmentName
    )

    ##requires NTFSSecurity

    $filesReport = [ordered]@{}

    if (Test-Path -Path $departmentPath -PathType Container)
    {
        $userAccessDepartmentFolder=Get-Item -Path $departmentPath | Get-NTFSEffectiveAccess -Account $userName | select Account, AccessRights, FullName
        $filesReport.Add("DepartmentFolderUserAccess", $userAccessDepartmentFolder)


        $groupAccessDepartmentFolder=Get-Item -Path $departmentPath | Get-NTFSEffectiveAccess -Account $groupName |select Account, AccessRights, FullName
        $filesReport.Add("DepartmentFolderGroupAccess",$groupAccessDepartmentFolder)
    
        $userPath=Join-Path -Path $departmentPath -ChildPath $userName.Substring($userName.IndexOf("\")+1)
        if (Test-Path -Path $userPath -PathType Container)
        {
            $userAccessUserFolder=Get-Item -Path $userPath | Get-NTFSEffectiveAccess -Account $userName | select Account, AccessRights, FullName
            $filesReport.Add("UserFolderUserAccess",$userAccessUserFolder)

            $groupAccessUserfolder=Get-Item -Path $userPath | Get-NTFSEffectiveAccess -Account $groupName |select Account, AccessRights, FullName
            $filesReport.Add("UserFolderGroupAccess",$groupAccessUserfolder)
        }
        else
        {
            $filesReport.Add("UserFolderUserAccess","UNSET")
            $filesReport.Add("UserFolderGroupAccess","UNSET")
        }
    }
    else
    {
        $filesReport.Add("DepartmentFolderUserAccess", "UNSET")
        $filesReport.Add("DepartmentFolderGroupAccess","UNSET")
        $filesReport.Add("UserFolderUserAccess","UNSET")
        $filesReport.Add("UserFolderGroupAccess","UNSET")
    }

    return $filesReport
}


###########################VARIABLES###################################
$monitoredOU="KOMPUTERY"
$computerList=(Get-ADComputer -Filter * -SearchBase "OU=$monitoredOU, DC=domena, DC=local").Name
$isConnected=Test-Connection -ComputerName $computerList -Quiet -Count 10

$userName="$env:USERDOMAIN\jnowak"
$groupName="$env:USERDOMAIN\Pracownicy_DP"
$departmentPath="\\$env:COMPUTERNAME\DP"

$pathToScript="C:\TEST\skrypt.ps1"
$isScriptExist=Test-Path -Path "C:\TEST\skrypt.ps1" -PathType Leaf

#######FO DATA AQUISITION##########
$softwareList = [ordered]@{
    "7-Zip"             = "*Igor Pavlov*" 
    "Adobe"             = "*Adobe*" 
    "Notepad++"         = "*Notepad++ Team*" 
    "Microsoft Edge"    = "*Microsoft*" 
    "Java 8"            = "*Oracle*" 
}

$filesReport=Get-FilesReport -userName $userName -groupName $groupName -departmentName $departmentPath

########################################################################
########################################################################
##                                                                    ##
##                             MAIN                                   ##
##                                                                    ##
########################################################################
########################################################################


#Current State
$gpoLast=Get-ADOrganizationalUnit -Filter {name -eq $monitoredOU} | Select-Object -ExpandProperty distinguishedname | Get-GPInheritance | Select-Object -ExpandProperty gpolinks | ForEach-Object {Get-GPO -Guid $_.gpoid} | Select-Object ModificationTime

while($true)
{
    Read-Host "Change GPO: "
    
    #Get data after change
    $gpoCurrent=Get-ADOrganizationalUnit -Filter {name -eq $monitoredOU} | Select-Object -ExpandProperty distinguishedname | Get-GPInheritance | Select-Object -ExpandProperty gpolinks | ForEach-Object {Get-GPO -Guid $_.gpoid} | Select-Object ModificationTime
    
    #Testing variables
    $isLastExist=[string]::IsNullOrEmpty($gpoLast)
    $isCurrentExist=[string]::IsNullOrEmpty($gpoCurrent)

    if ((-not($isLastExist)) -and (-not($isCurrentExist))) # 11
    {
        $isTimeDifference=Compare-Object -ReferenceObject $gpoLast.ModificationTime -DifferenceObject $gpoCurrent.ModificationTime
        $isTimeExist=[string]::IsNullOrEmpty($isTimeDifference)
        
        if (-not($isTimeExist) -and $isConnected -and $isScriptExist)
        {
            Invoke-Command -ComputerName $computerList -FilePath $pathToScript -ArgumentList $softwareList,$filesReport
        }
        else
        {
            "Oba się pełne i są takie same"
        }

    }
    if ((-not($isLastExist)) -and $isCurrentExist -and $isConnected) # 10
    {
        Invoke-Command -ComputerName $computerList -FilePath $pathToScript -ArgumentList $softwareList,$filesReport
    }
    if ($isLastExist -and (-not($isCurrentExist)) -and $isConnected -and $isScriptExist) # 01
    {
        Invoke-Command -ComputerName $computerList -FilePath $pathToScript -ArgumentList $softwareList,$filesReport
    }
    if ($isLastExist -and $isCurrentExist -and $isScriptExist) # 00
    {
        "Obie są puste - bez zmian"
    }

    $gpoLast=$gpoCurrent 
    Start-Sleep -Seconds 5
}


