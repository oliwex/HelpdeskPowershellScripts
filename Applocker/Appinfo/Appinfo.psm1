<#
    .SYNOPSIS
    Loads function into module
    
    .DESCRIPTION
    This is autoloader for function in module
    
    .LIST OF APPLICATIONS
    Get-ApplockerListOfApps

    .LINK
    Applocker
    https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/applocker/what-is-applocker
#>

$functionPath=$PSScriptRoot + "\Functions\"

$functionList=Get-ChildItem -Path $functionPath -Name

foreach($function in $functionList)
{
    . ($functionPath + $function)
}
