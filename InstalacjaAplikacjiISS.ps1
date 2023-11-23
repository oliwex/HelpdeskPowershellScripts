
###########################################################
function Get-Connection
{
    [CmdletBinding()]
    param (
        [Parameter(HelpMessage = "Packet name to install application")]
        [Alias("Computers")]
        [string]$packetName
    )

    $path=(Get-Location).Path
    $issFilepath=(Get-ChildItem -Path $path).Name

    $computerNames=Get-Content -Path $(Join-Path -Path $path -ChildPath "stacje.txt")

    $output=[PSCustomObject]@{}

    $computerNames | ForEach-Object {

        $output | Add-Member -MemberType "NoteProperty" -Name $($_) -Value $($_)

        $connection=(Test-Path "\\$($_)\C$")
        
        if ($connection)
        {
            $output | Add-Member -MemberType "NoteProperty" -Name $($_) -Value $connection

            $tempInstallationPath="\\$($_)\instalacje\$packetName"
            if (-not(Test-Path -Path $tempInstallationPath))
            {
                New-Item -Path $tempInstallationPath -ItemType Directory
            }
            
            $installPacketPath=Join-Path -Path $path -ChildPath $packetName
            Copy-Item -Path $installPacketPath -Destination $tempInstallationPath -Recurse

            $pstoolsPath = "\\$($_)\C$\Windows\System32"
            if (-not (Test-Path -Path $pstoolsPath))
            {
                Copy-Item -Path "$path\pstools\PsExec.exe" -Destination $pstoolsPath
            }

            pstools\psexec -accepteula -nobanner \\$($_) "$tempInstallationPath\setup.exe" -s -f1"$issFilePath\setup.iss"

            Remove-Item -Path $tempInstallationPath -Recurse

            $applicationName=$packetName.Split("_")[0]

            if(Test-Path -Path "\\$($_)\C$\$applicationName\$applicationName.exe" -PathType leaf)
            {
                $output | Add-Member -MemberType "NoteProperty" -Name Version -Value (((Get-ChildItem -Path "\\$($_)\C`$\$applicationName\$applicationName.exe").VersionInfo).ProductVersion)
            }
            else 
            {
                $output | Add-Member -MemberType "NoteProperty" -Name Version -Value "ERROR"
            }
        }
        else
        {
            $output | Add-Member -MemberType "NoteProperty" -Name $($_) -Value "Not Available"
            $output | Add-Member -MemberType "NoteProperty" -Name Version -Value "Not Connected" 
        }
    }
    $output
}
