#TODO
#Procent spełnienia założeń skryptu: % CHANGED i  % UNCHANGED
##########################FUNCTIONS####################################
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

function Test-Workplace
{    
[CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true,HelpMessage="ReportPath",Position=0)]
        $scriptHashtable,
        [Parameter(Mandatory=$true,HelpMessage="ComputerToMonitor",Position=1)]
        [String]$computerToMonitor
    )

    do
    {
        $scriptPathTest=$false
        $reportPathTest=$false
        $rootPath=Read-Host "Podaj ścieżkę do plików skryptowych:"
        $isScriptPathNull=[string]::IsNullorEmpty($rootPath)
        
        if ($isScriptPathNull)
        {
            continue
        }
        else
        {
            $scriptPath=Join-Path -Path $rootPath -ChildPath $scriptHashtable["Skrypt"]
            $reportPath=Join-Path -Path $rootPath -ChildPath $scriptHashtable["Generator"]
            $scriptPathTest=Test-Path -Path $scriptPath -PathType Leaf
            $reportPathTest=Test-Path -Path $reportPath -PathType Leaf
        }
        $connecetion=Test-Connection -ComputerName $computerToMonitor -Quiet
        
        $installedModule=(($(Get-InstalledModule).Name).Contains("NTFSSecurity"))
        if (-not($installedModule))
        {
            Install-Module -Name NTFSSEcurity -AllowClobber
        }
    }
    until ($scriptPathTest -and $reportPathTest -and $connecetion -and $installedModule)
    return $rootPath
}

function Get-FilesReport
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true,HelpMessage="UserInformation",Position=0)]
        $userInformation
    )

    ##requires NTFSSecurity
    $filesReport = [ordered]@{}

    $departmentPath=Join-Path -Path $($userInformation.PathToSharedFolder) -ChildPath $($userInformation.Department)
    if (Test-Path -Path $departmentPath -PathType Container)
    {
            $userAccessDepartmentFolder=Get-Item -Path $departmentPath | Get-NTFSEffectiveAccess -Account $($userInformation.Username) | select Account, AccessRights, FullName
            if ($userAccessDepartmentFolder.AccessRights -like "WriteExtendedAttributes, WriteAttributes, ReadAndExecute, Synchronize")
            {
                $userAccessDepartmentFolder.AccessRights="SET"
            }
            else
            {
                $userAccessDepartmentFolder.AccessRights="UNSET"
            }
            $filesReport.Add("DepartmentFolderUserAccess", $userAccessDepartmentFolder)


            $groupAccessDepartmentFolder=Get-Item -Path $departmentPath | Get-NTFSEffectiveAccess -Account $($userInformation.Groupname) | select Account, AccessRights, FullName
            if ($groupAccessDepartmentFolder.AccessRights -like "WriteExtendedAttributes, WriteAttributes, ReadAndExecute, Synchronize")
            {
                $groupAccessDepartmentFolder.AccessRights="SET"
            }
            else
            {
                $groupAccessDepartmentFolder.AccessRights="UNSET"
            }

            $filesReport.Add("DepartmentFolderGroupAccess",$groupAccessDepartmentFolder)
    
        $userPath=Join-Path -Path $($userInformation.PathToSharedFolder) -ChildPath $($userInformation.Username)
        if (Test-Path -Path $userPath -PathType Container)
        {
            $userAccessUserFolder=Get-Item -Path $userPath | Get-NTFSEffectiveAccess -Account $($userInformation.Username) | select Account, AccessRights, FullName
            if ($userAccessUserFolder.AccessRights -like "Write, ReadAndExecute, Synchronize")
            {
                $userAccessUserFolder.AccessRights="SET"
            }
            else
            {
                $userAccessUserFolder.AccessRights="UNSET"
            }
            $filesReport.Add("UserFolderUserAccess",$userAccessUserFolder)

            $groupAccessUserfolder=Get-Item -Path $userPath | Get-NTFSEffectiveAccess -Account $($userInformation.Groupname) | select Account, AccessRights, FullName
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

function Get-UserInformation
{
    do
    {
            $userName=Read-Host "Podaj nazwę użytkownika"
            $isUsernameNull=[string]::IsNullorEmpty($userName)
        
            $groupName=Read-Host "Podaj nazwę grupy"
            $isGroupNull=[string]::IsNullorEmpty($groupName)

            $departmentName=Read-Host "Podaj nazwę departamentu"
            $isDepartmentNull=[string]::IsNullorEmpty($departmentName)


            $isUserExist=((Get-ADUser -Filter *).SamAccountName).Contains($userName)
            $isGroupExist=((Get-ADGroup -Filter *).Name).Contains($groupName)

    }
    until (($isUserExist) -and ($isGroupExist) -and (-not($isDepartmentNull)))
    
    $files = [ordered]@{
    Username             = $userName
    Groupname            = $groupName
    PathToSharedFolder   = "\\$env:COMPUTERNAME"
    Department           = $departmentName
    }
    return $files
}

###########################VARIABLES###################################
$computerToMonitor="HOST"
$monitoredOU="KOMPUTERY"

#######FOR DATA AQUISITION##########
$softwareList = [ordered]@{
    "7-Zip"             = "*Igor Pavlov*" 
    "Adobe"             = "*Adobe*" 
    "Notepad++"         = "*Notepad++ Team*" 
    "Microsoft Edge"    = "*Microsoft*" 
    "Java 8"            = "*Oracle*" 
}


$scriptHashtable = [ordered]@{
Skrypt     = "skrypt.ps1" 
Generator  = "reportGenerator.ps1" 
}

########################################################################
########################################################################
##                                                                    ##
##                             MAIN                                   ##
##                                                                    ##
########################################################################
########################################################################


$rootPath=Test-Workplace -scriptHashtable $scriptHashtable -computerToMonitor $computerToMonitor
$scriptPath=Join-Path -Path $rootPath -ChildPath $scriptHashtable["Skrypt"]
$generatorPath=Join-Path -Path $rootPath -ChildPath $scriptHashtable["Generator"]



$resultPath=$(Get-ReportPath)
$logPath=$(Get-LogPath -computerToMonitor $computerToMonitor)
New-InformationLog -logPath $logPath -message "Zebranie informacji o potrzebnych folderach logowania oraz raportowania" -color green


#Current State
New-InformationLog -logPath $logPath -message "Zebranie informacji o obecnym stanie polityk GPO" -color green
$gpoLast=Get-ADOrganizationalUnit -Filter {name -eq $monitoredOU} | Select-Object -ExpandProperty distinguishedname | Get-GPInheritance | Select-Object -ExpandProperty gpolinks | ForEach-Object {Get-GPO -Guid $_.gpoid} | Select-Object ModificationTime


while($true)
{
    New-InformationLog -logPath $logPath -message "Zebranie informacji o udziałach sieciowych" -color green
    $userData=Get-UserInformation
    $filesReport=Get-FilesReport -userInformation $userData

    New-InformationLog -logPath $logPath -message "Zebranie informacji o pliku raportowym" -color green
    $resultFile=$(Get-ReportFile -reportPath $resultPath -computerToMonitor $computerToMonitor)

    Read-Host "Change GPO: "
    New-InformationLog -logPath $logPath -message "Sprawdzenie stanu polityk po zmianie" -color green

    $isLastExist=[string]::IsNullOrEmpty($gpoLast)
    $gpoCurrent=Get-ADOrganizationalUnit -Filter {name -eq $monitoredOU} | Select-Object -ExpandProperty distinguishedname | Get-GPInheritance | Select-Object -ExpandProperty gpolinks | ForEach-Object {Get-GPO -Guid $_.gpoid} | Select-Object ModificationTime
    $isCurrentExist=[string]::IsNullOrEmpty($gpoCurrent)


    if (($isLastExist -eq $true) -and ($isCurrentExist -eq $true))
    {
        New-InformationLog -logPath $logPath -message "Polityki nie istniają zarówno przed oraz po sprawdzeniu" -color red
    }

    if (($isLastExist -eq $false) -and ($isCurrentExist -eq $true))
    {
        "1=POLITYKA,2=NULL"
        New-InformationLog -logPath $logPath -message "Polityki zostały zmienione. Następuje odwołanie do zdalnego hosta" -color green
        $fullReport=Invoke-Command -ComputerName $computerToMonitor -FilePath $scriptPath -ArgumentList $filesReport,$softwareList

        New-InformationLog -logPath $logPath -message "Dane zostały zebrane.Zostaje wykonany raport." -color green
        
        Invoke-Command -ComputerName $($env:COMPUTERNAME) -FilePath $generatorPath -ArgumentList $fullReport,$computerToMonitor,$resultFile

        
        New-InformationLog -logPath $logPath -message "Raport został wykonany. Można go zobaczyć w: $resultFile" -color green
    }



    if (($isLastExist -eq $true) -and ($isCurrentExist -eq $false))
    {
        "1=NULL,2=POLITYKA"
        New-InformationLog -logPath $logPath -message "Polityki zostały zmienione. Następuje odwołanie do zdalnego hosta" -color green
        $fullReport=Invoke-Command -ComputerName $computerToMonitor -FilePath $scriptPath -ArgumentList $filesReport,$softwareList

        New-InformationLog -logPath $logPath -message "Dane zostały zebrane.Zostaje wykonany raport." -color green
        Invoke-Command -ComputerName $($env:COMPUTERNAME) -FilePath $generatorPath -ArgumentList $fullReport,$computerToMonitor,$resultFile
        
        New-InformationLog -logPath $logPath -message "Raport został wykonany. Można go zobaczyć w: $resultFile" -color green
    }


    if (($testLastNull -eq $false) -and ($testCurrentNull -eq $false))
    {
        "1=POLITYKA,2=POLITYKA"
        New-InformationLog -logPath $logPath -message "Polityki istnieją w obu przypadkach. Następuje porównanie polityk pod kątem wykonanych zmian" -color green
        
        $testCompare=Compare-Object -Property DisplayName,Id,ModificationTime -ReferenceObject $gpoLast -DifferenceObject $gpoCurrent
        $isDifferenceExist=[string]::IsNullOrEmpty($testCompare)
        if ($isDifferenceExist -eq $false)
        {
            "POLITYKI ISTNIEJĄ I ZOSTAŁY WYKONANE ZMIANY"
            New-InformationLog -logPath $logPath -message "Polityki zostały zmienione. Następuje odwołanie do zdalnego hosta" -color green
            $fullReport=Invoke-Command -ComputerName $computerToMonitor -FilePath $scriptPath -ArgumentList $filesReport,$softwareList

            New-InformationLog -logPath $logPath -message "Dane zostały zebrane.Zostaje wykonany raport." -color green
            Invoke-Command -ComputerName $($env:COMPUTERNAME) -FilePath $generatorPath -ArgumentList $fullReport,$computerToMonitor,$resultFile
            
            New-InformationLog -logPath $logPath -message "Raport został wykonany. Można go zobaczyć w: $resultFile" -color green
        }
    }
    New-InformationLog -logPath $logPath -message "Następuje przekazanie stanu obecnego do stanu poprzedniego" -color green
    $gpoLast=$gpoCurrent 
    Start-Sleep -Seconds 5
}
