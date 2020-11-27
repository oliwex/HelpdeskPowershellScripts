#TODO
#Sprawdzenie, czy komputer jest połączony
#Sprawdzenie, czy skrypt jest umieczony w folderze
#Ilość pamięci nie działa odpowiednio
#Dane instalacji programów są nieodpowiednie
#odpowiednie tłumaczenie uprawnień do udziałów sieciowych
#sprawdzenie czy są odpowiednie moduły
#Procent spełnienia założeń skryptu: % CHANGED i  % UNCHANGED
#Kolorystyka raportów
##########################FUNCTIONS####################################

function Get-FilesReport
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true,HelpMessage="UserName.",Position=0)]
        [String]$userName,
        [Parameter(Mandatory=$true,HelpMessage="GroupName",Position=1)]
        [String]$groupName,
        [Parameter(Mandatory=$true,HelpMessage="PathToSharedFolder",Position=2)]
        [String]$pathToSharedFolder,
        [Parameter(Mandatory=$true,HelpMessage="DepartmentName",Position=3)]
        [String]$departmentName
    )

    ##requires NTFSSecurity

    $filesReport = [ordered]@{}

    $departmentPath=Join-Path -Path $pathToSharedFolder -ChildPath $departmentName
    if (Test-Path -Path $departmentPath -PathType Container)
    {
            $userAccessDepartmentFolder=Get-Item -Path $departmentPath | Get-NTFSEffectiveAccess -Account $userName | select Account, AccessRights, FullName
            if ($userAccessDepartmentFolder.AccessRights -like "WriteExtendedAttributes, WriteAttributes, ReadAndExecute, Synchronize")
            {
                $userAccessDepartmentFolder.AccessRights="SET"
            }
            else
            {
                $userAccessDepartmentFolder.AccessRights="UNSET"
            }
            $filesReport.Add("DepartmentFolderUserAccess", $userAccessDepartmentFolder)


            $groupAccessDepartmentFolder=Get-Item -Path $departmentPath | Get-NTFSEffectiveAccess -Account $groupName | select Account, AccessRights, FullName
            if ($groupAccessDepartmentFolder.AccessRights -like "WriteExtendedAttributes, WriteAttributes, ReadAndExecute, Synchronize")
            {
                $groupAccessDepartmentFolder.AccessRights="SET"
            }
            else
            {
                $groupAccessDepartmentFolder.AccessRights="UNSET"
            }

            $filesReport.Add("DepartmentFolderGroupAccess",$groupAccessDepartmentFolder)
    
        $userPath=Join-Path -Path $pathToSharedFolder -ChildPath $userName.Substring($userName.IndexOf("\"))
        if (Test-Path -Path $userPath -PathType Container)
        {
            $userAccessUserFolder=Get-Item -Path $userPath | Get-NTFSEffectiveAccess -Account $userName | select Account, AccessRights, FullName
            if ($userAccessUserFolder.AccessRights -like "Write, ReadAndExecute, Synchronize")
            {
                $userAccessUserFolder.AccessRights="SET"
            }
            else
            {
                $userAccessUserFolder.AccessRights="UNSET"
            }
            $filesReport.Add("UserFolderUserAccess",$userAccessUserFolder)

            $groupAccessUserfolder=Get-Item -Path $userPath | Get-NTFSEffectiveAccess -Account $groupName | select Account, AccessRights, FullName
            if ($groupAccessUserfolder.AccessRights -like "Synchronize")
            {
                $groupAccessUserfolder.AccessRights="SET"
            }
            else
            {
                $groupAccessUserfolder.AccessRights="UNSET"
            }
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
function Get-ReportPath
{
    $path=Read-Host -Prompt "Podaj ścieżkę do raportowania"
    $testPath=Test-Path -Path $path -PathType Container
    if (-not($testPath))
    {
        New-Item -Path $path -ItemType Directory
    }

    $datetime=Get-Date -Format "HH.mm_MM.dd.yyyy"
    $fileName="$computerToMonitor-$datetime.html"
    $reportPath=Join-Path -Path $path -ChildPath $fileName
    return $reportPath
}


###########################VARIABLES###################################
$computerToMonitor="HOST1"


$userName="$env:USERDOMAIN\jnowak"
$groupName="$env:USERDOMAIN\Pracownicy_DP"
$pathToSharedFolder="\\$env:COMPUTERNAME"
$departmentName="DP"

$pathToScript="C:\TEST\skrypt.ps1"
$pathToReportGenerator="C:\TEST\reportGenerator.ps1"

#######FOR DATA AQUISITION##########
$softwareList = [ordered]@{
    "7-Zip"             = "*Igor Pavlov*" 
    "Adobe"             = "*Adobe*" 
    "Notepad++"         = "*Notepad++ Team*" 
    "Microsoft Edge"    = "*Microsoft*" 
    "Java 8"            = "*Oracle*" 
}

$filesReport=Get-FilesReport -userName $userName -groupName $groupName -pathToSharedFolder $pathToSharedFolder -department $departmentName


########################################################################
########################################################################
##                                                                    ##
##                             MAIN                                   ##
##                                                                    ##
########################################################################
########################################################################


$reportPath=Get-ReportPath


#Current State
$gpoLast=Get-ADOrganizationalUnit -Filter {name -eq $monitoredOU} | Select-Object -ExpandProperty distinguishedname | Get-GPInheritance | Select-Object -ExpandProperty gpolinks | ForEach-Object {Get-GPO -Guid $_.gpoid} | Select-Object ModificationTime

while($true)
{
    Read-Host "Change GPO: "
    $isLastExist=[string]::IsNullOrEmpty($gpoLast)
    $gpoCurrent=Get-ADOrganizationalUnit -Filter {name -eq $monitoredOU} | Select-Object -ExpandProperty distinguishedname | Get-GPInheritance | Select-Object -ExpandProperty gpolinks | ForEach-Object {Get-GPO -Guid $_.gpoid} | Select-Object ModificationTime
    $isCurrentExist=[string]::IsNullOrEmpty($gpoCurrent)
    if (($isLastExist -eq $true) -and ($isCurrentExist -eq $true))
    {
    "Brak polityk w obu przypadkach"
    }
    if (($isLastExist -eq $false) -and ($isCurrentExist -eq $true))
    {
        "1=POLITYKA,2=NULL"
        $fullReport=Invoke-Command -ComputerName $computerToMonitor -FilePath $pathToScript -ArgumentList $softwareList,$filesReport
        "raportuj"
        & $pathToReportGenerator "$fullReport","$computerToMonitor","$reportPath"
    }
    if (($isLastExist -eq $true) -and ($isCurrentExist -eq $false))
    {
        "1=NULL,2=POLITYKA"
        $fullReport=Invoke-Command -ComputerName $computerToMonitor -FilePath $pathToScript -ArgumentList $softwareList,$filesReport
        "raportuj"
        & $pathToReportGenerator "$fullReport","$computerToMonitor","$reportPath"
    }
    if (($testLastNull -eq $false) -and ($testCurrentNull -eq $false))
    {
        "1=POLITYKA,2=POLITYKA"
        "POLITYKI ISTNIEJĄ ALE BRAK ZMIAN"
        $testCompare=Compare-Object -Property DisplayName,Id,ModificationTime -ReferenceObject $gpoLast -DifferenceObject $gpoCurrent
        $isDifferenceExist=[string]::IsNullOrEmpty($testCompare)
        if ($isDifferenceExist -eq $false)
        {
            "POLITYKI ISTNIEJĄ I ZOSTAŁY WYKONANE ZMIANY"
            $fullReport=Invoke-Command -ComputerName $computerToMonitor -FilePath $pathToScript -ArgumentList $softwareList,$filesReport
            "raportuj"
            & $pathToReportGenerator "$fullReport","$computerToMonitor","$reportPath"
        }
    }
    $gpoLast=$gpoCurrent 
    Start-Sleep -Seconds 5
}
