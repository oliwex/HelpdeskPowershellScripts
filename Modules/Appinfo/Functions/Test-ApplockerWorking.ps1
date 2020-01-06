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

    .LINK
    Applocker
    https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/applocker/what-is-applocker

    .EXAMPLE
    Test-Applocker

    #>
    ((Get-Service *AppIDSvc*).Status -eq "Running")
}

Test-Applocker