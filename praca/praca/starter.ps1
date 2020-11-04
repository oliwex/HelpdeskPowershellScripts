#TODO
#Skrypt dławi się przed wejściem do pętli
#Sprawdzenie, czy komputer jest połączony
#Sprawdzenie, czy skrypt jest umieczony w folderze
#Ilość pamięci nie działa odpowiednio
#Sprawdzenie, czy są odpowiednie warunki zmian
#sprawdzenie czy są odpowiednie moduły
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


$userName="$env:USERDOMAIN\jnowak"
$groupName="$env:USERDOMAIN\Pracownicy_DP"
$departmentPath="\\$env:COMPUTERNAME\DP"

$pathToScript="C:\TEST\skrypt.ps1"
$isScriptExist=Test-Path -Path $pathToScript -PathType Leaf
#######FOR DATA AQUISITION##########
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
    "Pobranie polityk różnicowych"
    
    #Testing variables
    $isLastExist=[string]::IsNullOrEmpty($gpoLast)
    $isCurrentExist=[string]::IsNullOrEmpty($gpoCurrent)
    
    "Sprawdzenie, czy są polityki i ich statusu"
    if ((-not($isLastExist)) -and (-not($isCurrentExist))) # 11
    {
        "Obie polityki istnieją"
        $isTimeDifference=Compare-Object -ReferenceObject $gpoLast.ModificationTime -DifferenceObject $gpoCurrent.ModificationTime
        $isTimeExist=[string]::IsNullOrEmpty($isTimeDifference)
        
        if (-not($isTimeExist))
        {
            "Istnieja różnice w politykach-wykonanie invoke" 
            $fullReport=Invoke-Command -ComputerName HOST1 -FilePath $pathToScript -ArgumentList $softwareList,$filesReport
            "#######################################"
            $fullReport
            invoke-command -ComputerName SERVER { &'c:\TEST\generator.ps1' } -ArgumentList $fullReport
        }
        else
        {
            "Obie polityki są skonfigurowane, ale nie zaszły zmiany"
        }

    }
    if ((-not($isLastExist)) -and $isCurrentExist) # 10
    {
        "usunieto wszystkie polityki"
        $fullReport=Invoke-Command -ComputerName HOST1 -FilePath $pathToScript -ArgumentList $softwareList,$filesReport
        "#######################################"
        $fullReport
        invoke-command -ComputerName SERVER { &'c:\TEST\generator.ps1' } -ArgumentList $fullReport
    }
    if ($isLastExist -and (-not($isCurrentExist)) -and $isConnected) # 01
    {
        "Dodano polityki"
        $fullReport=Invoke-Command -ComputerName HOST1 -FilePath $pathToScript -ArgumentList $softwareList,$filesReport
        "#######################################"
        $fullReport
        invoke-command -ComputerName SERVER { &'c:\TEST\generator.ps1' } -ArgumentList $fullReport
    }
    if ($isLastExist -and $isCurrentExist) # 00
    {
        "Brak polityk przed i po sprawdzeniu"
    }

    $gpoLast=$gpoCurrent 
    Start-Sleep -Seconds 5
}


