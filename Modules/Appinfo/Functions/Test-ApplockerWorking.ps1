function Test-ApplockerWorking
{
    <#
    .SYNOPSIS
    Test if Applocker work
    
    .DESCRIPTION
    Function test if applocker works in operting system.
    
    .OUTPUTS
    True or False
    
    .LINK
    Get-Service
    https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.management/get-service?view=powershell-6
    Get-CimInstance
    https://docs.microsoft.com/en-us/powershell/module/cimcmdlets/get-ciminstance?view=powershell-7

    .LINK
    Applocker
    https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/applocker/what-is-applocker

    .EXAMPLE
    Test-ApplockerWorking

    .OUTPUT
    Returns information about Applocker can run or not

    #>

    $osApprove="Microsoft Windows 7 Professional ",
    "Microsoft Windows 7 Enterprise ",
    "Microsoft Windows 7 Ultimate ",
    "Microsoft Windows Server 2008 R2 for Itanium-Based Systems ",
    "Microsoft Windows Server 2008 R2 Datacenter ",
    "Microsoft Windows Server 2008 R2 Enterprise ",
    "Microsoft Windows Server 2008 R2 Standard ",
    "Microsoft Windows RT ",
    "Microsoft Windows 8 Enterprise ",
    "Microsoft Windows 8 Pro ",
    "Microsoft Windows RT 8.1 ",
    "Microsoft Windows 8.1 Enterprise ",
    "Microsoft Windows 8.1 Pro ",
    "Microsoft Windows Server 2012 ",
    "Microsoft Windows Server 2012 R2 ",
    "Microsoft Windows Server 2016 ",
    "Microsoft Windows Server 2019 ",
    "Microsoft Windows 10 "

    if (($osApprove.Contains((Get-CimInstance Win32_OperatingSystem).Caption)) -and ((Get-Service *AppIDSvc*).Status -eq 'Running'))
    {

        Write-Host  "Test Operating System: "$($osApprove.Contains($os)) -ForegroundColor Green -BackgroundColor Black
        Write-Host  "Test Service System: "((Get-Service *AppIDSvc*).Status -eq 'Running') -ForegroundColor Green -BackgroundColor Black
    }
    else
    {
         Write-Host  "Probably Error with Operating system or AppIDSvc service is not running" -ForegroundColor Green -BackgroundColor Black
    }  
}


