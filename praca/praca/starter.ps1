#TODO
#Sprawdzenie, czy komputer jest połączony
#Sprawdzenie, czy skrypt jest umieczony w folderze
#Ilość pamięci nie działa odpowiednio
#Dane instalacji programów są nieodpowiednie
#odpowiednie tłumaczenie uprawnień do udziałów sieciowych
#sprawdzenie czy są odpowiednie moduły
#Procent spełnienia założeń skryptu: % CHANGED i  % UNCHANGED
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

    do
    {
        $isIdentical=$true
        $reportPath=Read-Host -Prompt "Podaj ścieżkę do raportowania zdarzeń"
        $isReportPathNull=[string]::IsNullorEmpty($reportPath)
        
        if ($isReportPathNull)
        {
            continue
        }
        else
        {
            $isIdentical=Test-Path -Path $reportPath -PathType Container
            if ($isIdentical)
            {
                continue
            }
            else
            {
                New-Item -Path $reportPath -ItemType Directory | Out-Null
            }
        }

    }
    until (-not($isIdentical))

    return $reportPath
}

function Get-ReportFile
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true,HelpMessage="ReportPath",Position=0)]
        [String]$reportPath,
        [Parameter(Mandatory=$true,HelpMessage="ComputerToMonitor",Position=1)]
        [String]$computerToMonitor
    )
    $datetime=Get-DateTime
    $fileName="$computerToMonitor-$datetime.html"
    $reportPath=Join-Path -Path $reportPath -ChildPath $fileName

    return $reportPath
}

function Get-DateTime
{
$datetime=Get-Date -Format "HH.mm.ss.ffff_dd.MM.yyyy"
return $datetime
}

function Get-LogPath
{
    [CmdletBinding()]
    Param(

        [Parameter(Mandatory=$true,HelpMessage="ComputerToMonitor",Position=0)]
        [String]$computerToMonitor
        )
    do
    {
        $isIdentical=$true
        $logPath=Read-Host -Prompt "Podaj ścieżkę do logowania zdarzeń:"
        $isLogPathNull=[string]::IsNullorEmpty($logPath)
        
        if ($isLogPathNull)
        {
            continue
        }
        else
        {
            $isIdentical=Test-Path -Path $logPath -PathType Container
            if ($isIdentical)
            {
                continue
            }
            else
            {
                New-Item -Path $logPath -ItemType Directory | Out-Null
            }
        }

    }
    until (-not($isIdentical))

    $datetime=Get-Date -Format "HH.mm_dd.MM.yyyy"
    $fileName="$computerToMonitor-$datetime.txt"
    $logFilePath=Join-Path -Path $logPath -ChildPath $fileName
    New-Item -Path $logPath -Name $fileName -ItemType File | Out-Null
    return  $logFilePath
}

function New-InformationLog
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true,HelpMessage="LogPath",Position=0)]
        [String]$logPath,
        [Parameter(Mandatory=$true,HelpMessage="Message",Position=1)]
        [String]$message,
        [Parameter(Mandatory=$true,HelpMessage="Color",Position=2)]
        [String]$color
        )

    $datetime=Get-DateTime
    "[$datetime] $message" >> $logPath
    if ($color -eq "red")
    {
        Write-Host "[$datetime] $message " -ForegroundColor Red
    }
    else
    {
        Write-Host "[$datetime] $message " -ForegroundColor Green
    }
}


###########################VARIABLES###################################
$computerToMonitor="HOST"
$monitoredOU="KOMPUTERY"

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

########################################################################
########################################################################
##                                                                    ##
##                             MAIN                                   ##
##                                                                    ##
########################################################################
########################################################################

$resultPath=$(Get-ReportPath)
$logPath=$(Get-LogPath -computerToMonitor $computerToMonitor)



New-InformationLog -logPath $logPath -message "Rozpoczęcie działania skryptu" -color green

$filesReport=Get-FilesReport -userName $userName -groupName $groupName -pathToSharedFolder $pathToSharedFolder -department $departmentName
New-InformationLog -logPath $logPath -message "Zebranie informacji o udziałach sieciowych" -color green


#Current State
$gpoLast=Get-ADOrganizationalUnit -Filter {name -eq $monitoredOU} | Select-Object -ExpandProperty distinguishedname | Get-GPInheritance | Select-Object -ExpandProperty gpolinks | ForEach-Object {Get-GPO -Guid $_.gpoid} | Select-Object ModificationTime
New-InformationLog -logPath $logPath -message "Zebranie informacji o obecnym stanie polityk GPO" -color green

while($true)
{

    $resultFile=$(Get-ReportFile -reportPath $resultPath -computerToMonitor $computerToMonitor)

    Read-Host "Change GPO: "
    $isLastExist=[string]::IsNullOrEmpty($gpoLast)
    $gpoCurrent=Get-ADOrganizationalUnit -Filter {name -eq $monitoredOU} | Select-Object -ExpandProperty distinguishedname | Get-GPInheritance | Select-Object -ExpandProperty gpolinks | ForEach-Object {Get-GPO -Guid $_.gpoid} | Select-Object ModificationTime
    $isCurrentExist=[string]::IsNullOrEmpty($gpoCurrent)

    New-InformationLog -logPath $logPath -message "Sprawdzenie stanu polityk" -color green

    if (($isLastExist -eq $true) -and ($isCurrentExist -eq $true))
    {
    "Brak polityk w obu przypadkach"
    New-InformationLog -logPath $logPath -message "Polityki nie istniają zarówno przed oraz po sprawdzeniu" -color red
    }



    if (($isLastExist -eq $false) -and ($isCurrentExist -eq $true))
    {
        "1=POLITYKA,2=NULL"
        New-InformationLog -logPath $logPath -message "Polityki zostały zmienione. Następuje odwołanie do zdalnego hosta" -color green

        $fullReport=Invoke-Command -ComputerName $computerToMonitor -FilePath $pathToScript -ArgumentList $softwareList,$filesReport
        New-InformationLog -logPath $logPath -message "Dane zostały zebrane.Zostaje wykonany raport." -color green
        "raportuj"
        & $pathToReportGenerator "$fullReport","$computerToMonitor","$resultFile"
        New-InformationLog -logPath $logPath -message "Raport został wykonany. Można go zobaczyć w: $resultFile" -color green
    }



    if (($isLastExist -eq $true) -and ($isCurrentExist -eq $false))
    {
        "1=NULL,2=POLITYKA"
        New-InformationLog -logPath $logPath -message "Polityki zostały zmienione. Następuje odwołanie do zdalnego hosta" -color green

        $fullReport=Invoke-Command -ComputerName $computerToMonitor -FilePath $pathToScript -ArgumentList $softwareList,$filesReport
        New-InformationLog -logPath $logPath -message "Dane zostały zebrane.Zostaje wykonany raport." -color green
        "raportuj"
        & $pathToReportGenerator "$fullReport","$computerToMonitor","$resultFile"
        New-InformationLog -logPath $logPath -message "Raport został wykonany. Można go zobaczyć w: $resultFile" -color green
    }


    if (($testLastNull -eq $false) -and ($testCurrentNull -eq $false))
    {
        "1=POLITYKA,2=POLITYKA"
        New-InformationLog -logPath $logPath -message "Polityki istnieją w obu przypadkach." -color green
        "POLITYKI ISTNIEJĄ ALE BRAK ZMIAN"
        $testCompare=Compare-Object -Property DisplayName,Id,ModificationTime -ReferenceObject $gpoLast -DifferenceObject $gpoCurrent
        $isDifferenceExist=[string]::IsNullOrEmpty($testCompare)
        if ($isDifferenceExist -eq $false)
        {
            New-InformationLog -logPath $logPath -message "Polityki zostały zmienione. Następuje odwołanie do zdalnego hosta" -color green
            "POLITYKI ISTNIEJĄ I ZOSTAŁY WYKONANE ZMIANY"
            $fullReport=Invoke-Command -ComputerName $computerToMonitor -FilePath $pathToScript -ArgumentList $softwareList,$filesReport
            New-InformationLog -logPath $logPath -message "Dane zostały zebrane.Zostaje wykonany raport." -color green
            "raportuj"
            & $pathToReportGenerator "$fullReport","$computerToMonitor","$resultFile"
            New-InformationLog -logPath $logPath -message "Raport został wykonany. Można go zobaczyć w: $resultFile" -color green
        }
    }
    $gpoLast=$gpoCurrent 
    Start-Sleep -Seconds 5
}
