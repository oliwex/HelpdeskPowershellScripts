####################SCRIPT FILES########################################
$scriptHashtable = [ordered]@{
Skrypt     = "skrypt.ps1" 
Generator  = "reportGenerator.ps1" 
}

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
    Write-Host "[$datetime] $message " -ForegroundColor $color
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
        $rootPath=Read-Host "Podaj ścieżkę przechowującą pliki skryptów:"
        $isScriptPathNull=[string]::IsNullorEmpty($rootPath)
        
        if ($isScriptPathNull)
        {
            New-InformationLog -logPath $logPath -message "Nie podano danych ścieżki." -color red
            continue
        }
        else
        {
            New-InformationLog -logPath $logPath -message "Podano prawidłowe dane. Następuje tworzenie pełnych ścieżek do plików." -color green
            $scriptPath=Join-Path -Path $rootPath -ChildPath $scriptHashtable["Skrypt"]
            $reportPath=Join-Path -Path $rootPath -ChildPath $scriptHashtable["Generator"]
            $scriptPathTest=Test-Path -Path $scriptPath -PathType Leaf
            $reportPathTest=Test-Path -Path $reportPath -PathType Leaf
            New-InformationLog -logPath $logPath -message "Wykonano sprawdzenie, czy pliki o nazwach: $($scriptHashtable["Skrypt"]) oraz $($scriptHashtable["Generator"]) znajdują się w $rootPath" -color green
        }
        $connecetion=Test-Connection -ComputerName $computerToMonitor -Quiet
        New-InformationLog -logPath $logPath -message "Wykonano sprawdzenie, czy istnieje połączenie między serwerem a stacjami roboczymi." -color green
        
        if ($connecetion)
        {
           New-InformationLog -logPath $logPath -message "Połączenie z komputerem: $computerToMonitor zostało nawiązane prawidłowo." -color green 
        }
        else
        {
           New-InformationLog -logPath $logPath -message "Połączenie z komputerem: $computerToMonitor nie zostało nawiązane." -color red 
        }



        $installedModule=(($(Get-InstalledModule).Name).Contains("NTFSSecurity"))
        New-InformationLog -logPath $logPath -message "Wykonano sprawdzenie, czy moduł jest zainstalowany na serwerze" -color green

        if (-not($installedModule))
        {
            Install-Module -Name NTFSSecurity -AllowClobber
            New-InformationLog -logPath $logPath -message "Moduł nie był zainstalowany, toteż wykonano jego instalacje." -color red
        }

    }
    until ($scriptPathTest -and $reportPathTest -and $connecetion -and $installedModule)

    New-InformationLog -logPath $logPath -message "Poprawnie sprawdzono środowisko serwera przed dalszą działalnością skryptu" -color green
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
        $reportPath=Read-Host -Prompt "Podaj ścieżkę do przechowującą pliki raportów"
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
    $reportFile=Join-Path -Path $reportPath -ChildPath $fileName
    New-InformationLog -logPath $logPath -message "Utworzono nazwę dla pliku raportującego" -color green
    return $reportFile
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
        $logPath=Read-Host -Prompt "Podaj ścieżkę do logowania zdarzeń"
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
            New-InformationLog -logPath $logPath -message "Pobrano dane użytkownika do weryfikacji udziałów sieciowych." -color green
            
            $groupName=Read-Host "Podaj nazwę grupy"
            $isGroupNull=[string]::IsNullorEmpty($groupName)
            New-InformationLog -logPath $logPath -message "Pobrano nazwę grupy do weryfikacji udziałów sieciowych." -color green
            
            $departmentName=Read-Host "Podaj nazwę departamentu"
            $isDepartmentNull=[string]::IsNullorEmpty($departmentName)
            New-InformationLog -logPath $logPath -message "Pobrano nazwę departamentu do weryfikacji udziałów sieciowych." -color green

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
    New-InformationLog -logPath $logPath -message "Utworzono strukturę danych z informacjami o użytkowniku do weryfikacji udziałów sieciowych" -color green
    return $files
}

function Get-ComputerInformation
{
    $computerInfo=$nulls
    do
    {
        $flag=$false
        $computerName=Read-Host "Podaj nazwę komputera zdalnego"
        $isComputerNull=[string]::IsNullOrEmpty($computerName)
        if (-not($isComputerNull))
        {
            try
            {
                $computerInfo=(Get-ADComputer -Identity $computerName ).DistinguishedName
            }
            catch [Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException]
            {
                continue
            }
            $computerList=(Get-ADComputer -Filter {OperatingSystem -like "Windows 10*"}).DistinguishedName

            if ($computerList.Contains($computerInfo))
            {
                $computerInfo=[ordered]@{
                Computer=$computerName;
                OU=((Get-ADComputer -Identity $computerName).DistinguishedName.Split(",")[1]).Split("=")[1];
                }
                $flag=$true
            }
            else
            {
            }
        }
    }
    until ($flag)
    return $computerInfo
}

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
$computerInformation=Get-ComputerInformation
$monitoredOU=$computerInformation["OU"]
$computerToMonitor=$computerInformation["Computer"]

$resultPath=$(Get-ReportPath)
$logPath=$(Get-LogPath -computerToMonitor $computerToMonitor)
New-InformationLog -logPath $logPath -message "Zebrano informacje o komputerze oraz OU do raportowania." -color green
New-InformationLog -logPath $logPath -message "Zebrano informacje o ścieżce do raportowania." -color green
New-InformationLog -logPath $logPath -message "Zebrano informacje o ścieżce do zapisywania zdarzeń." -color green

$rootPath=Test-Workplace -scriptHashtable $scriptHashtable -computerToMonitor $($computerInformation["Computer"])
New-InformationLog -logPath $logPath -message "Sprawdzono, czy system jest gotowy na wykonanie skryptu." -color green

$scriptPath=Join-Path -Path $rootPath -ChildPath $($scriptHashtable["Skrypt"])
New-InformationLog -logPath $logPath -message "Utworzono ścieżkę do skryptu pobierającego dane z systemu zewnętrznego." -color green

$generatorPath=Join-Path -Path $rootPath -ChildPath $($scriptHashtable["Generator"])
New-InformationLog -logPath $logPath -message "Utworzono ścieżkę do skryptu generującego raport." -color green

#Current State
$gpoLast=(((Get-ADOrganizationalUnit -Filter {Name -eq $monitoredOU}).distinguishedname | Get-GPInheritance).GpoLinks | ForEach-Object {Get-GPO -Guid $_.gpoid}).ModificationTime
New-InformationLog -logPath $logPath -message "Zebrano informacje o obecnym stanie polityk GPO" -color green

while($true)
{
    
    $userData=Get-UserInformation
    New-InformationLog -logPath $logPath -message "Zebrano informacje o danych użytkownikach potrzebnych do weryfikacji uprawnień do udziałów sieciowych" -color green
    
    $filesReport=Get-FilesReport -userInformation $userData
    New-InformationLog -logPath $logPath -message "Zebrano informacje o udziałach sieciowych" -color green
    
    
    $resultFile=$(Get-ReportFile -reportPath $resultPath -computerToMonitor $computerToMonitor)
    New-InformationLog -logPath $logPath -message "Zebrano informacje o nazwie pliku raportowego" -color green


    $endVar=Read-Host "Proszę zmienić GPO lub wpisać koniec, jeśli skrypt ma zostać zakończony"
    if ($endVar -like "koniec")
    {
        New-InformationLog -logPath $logPath -message "Wywołano zakończenie skryptu" -color cyan
        break
    }
    New-InformationLog -logPath $logPath -message "Użytkownik został poproszony o wykonanie zmian w GPO" -color green

    $isLastExist=[string]::IsNullOrEmpty($gpoLast)
    $gpoCurrent=(((Get-ADOrganizationalUnit -Filter {Name -eq $monitoredOU}).distinguishedname | Get-GPInheritance).GpoLinks | ForEach-Object {Get-GPO -Guid $_.gpoid}).ModificationTime
    New-InformationLog -logPath $logPath -message "Pobrano obecny stan polityk" -color green
    $isCurrentExist=[string]::IsNullOrEmpty($gpoCurrent)
    New-InformationLog -logPath $logPath -message "Sprawdzono, czy polityki nie są puste" -color green

    if (($isLastExist -eq $true) -and ($isCurrentExist -eq $true))
    {
        New-InformationLog -logPath $logPath -message "Polityki nie istniają zarówno przed oraz po sprawdzeniu" -color red
    }

    if (($isLastExist -eq $false) -and ($isCurrentExist -eq $true))
    {
        #1=POLITYKA,2=NULL
        New-InformationLog -logPath $logPath -message "Polityki zostały zmienione. Następuje odwołanie do zdalnego hosta" -color green
        $fullReport=Invoke-Command -ComputerName $computerToMonitor -FilePath $scriptPath -ArgumentList $filesReport,$softwareList

        New-InformationLog -logPath $logPath -message "Dane zostały zebrane.Zostaje wykonany raport." -color green
        Invoke-Command -ComputerName $($env:COMPUTERNAME) -FilePath $generatorPath -ArgumentList $fullReport,$computerToMonitor,$resultFile
        
        New-InformationLog -logPath $logPath -message "Raport został wykonany. Można go zobaczyć w: $resultFile" -color green
    }



    if (($isLastExist -eq $true) -and ($isCurrentExist -eq $false))
    {
        #1=NULL,2=POLITYKA
        New-InformationLog -logPath $logPath -message "Polityki zostały zmienione. Następuje odwołanie do zdalnego hosta" -color green
        $fullReport=Invoke-Command -ComputerName $computerToMonitor -FilePath $scriptPath -ArgumentList $filesReport,$softwareList

        New-InformationLog -logPath $logPath -message "Dane zostały zebrane.Zostaje wykonany raport." -color green
        Invoke-Command -ComputerName $($env:COMPUTERNAME) -FilePath $generatorPath -ArgumentList $fullReport,$computerToMonitor,$resultFile
        
        New-InformationLog -logPath $logPath -message "Raport został wykonany. Można go zobaczyć w: $resultFile" -color green
    }


    if (($isLastExist -eq $false) -and ($isCurrentExist -eq $false))
    {
        #1=POLITYKA,2=POLITYKA
        New-InformationLog -logPath $logPath -message "Polityki istnieją w obu przypadkach. Następuje porównanie polityk pod kątem wykonanych zmian" -color green
        
        $testCompare=Compare-Object -Property DisplayName,Id,ModificationTime -ReferenceObject $gpoLast -DifferenceObject $gpoCurrent
        $isDifferenceExist=[string]::IsNullOrEmpty($testCompare)
        if ($isDifferenceExist -eq $false)
        {
            #1=POLITYKA,2=POLITYKA,3=CHANGED
            New-InformationLog -logPath $logPath -message "Polityki zostały zmienione. Następuje odwołanie do zdalnego hosta" -color green
            $fullReport=Invoke-Command -ComputerName $computerToMonitor -FilePath $scriptPath -ArgumentList $filesReport,$softwareList

            New-InformationLog -logPath $logPath -message "Dane zostały zebrane.Zostaje wykonany raport." -color green
            Invoke-Command -ComputerName $($env:COMPUTERNAME) -FilePath $generatorPath -ArgumentList $fullReport,$computerToMonitor,$resultFile
            
            New-InformationLog -logPath $logPath -message "Raport został wykonany. Można go zobaczyć w: $resultFile" -color green
        }
        else
        {
            New-InformationLog -logPath $logPath -message "Nie wykonano zmian w politykach" -color red
        }
    }
    New-InformationLog -logPath $logPath -message "Następuje przekazanie stanu obecnego do stanu poprzedniego" -color green
    $gpoLast=$gpoCurrent 
    New-InformationLog -logPath $logPath -message "Obecna iteracja skryptu została zakończona" -color green
    Start-Sleep -Seconds 5
}
New-InformationLog -logPath $logPath -message "Skrypt zakończony" -color green