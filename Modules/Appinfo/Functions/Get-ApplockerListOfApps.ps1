﻿function Get-ApplockerListofApps
{
    <#
    .SYNOPSIS
    Gets the domain controller of the current computer's domain, or for a 
    specific domain.
    
    .DESCRIPTION
    When having a policy with Applocker is important to control Applocker apps execution. So this function gets the list of apps with counter how many times apps was executed.
    
    .OUTPUTS
    Dictionary with list of apps and counter of apps executed
    
    .LINK
    Get-ApplockerFileInformation
    https://docs.microsoft.com/en-us/powershell/module/applocker/get-applockerfileinformation?view=win10-ps

    .LINK
    Applocker
    https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/applocker/what-is-applocker
    
    .EXAMPLE
    Get-ApplockerListOfApps

    .OUTPUT
    List of Apps which is used by user and how many times is used ex.
    Name        |   Value
    Chrome.exe  |     3
    Word.exe    |     2
    Excel.exe   |     1
    #>


    $list=Get-AppLockerFileInformation -EventLog -Statistics | Select FilePath,Counter

    if ($list.Count -gt 0)
    {
        $list=foreach($element in $list)
        {
            $element.FilePath=$element.FilePath.Path.Substring($element.FilePath.Path.LastIndexOf("\")+1)
            $element

        }

        $dictionary = @{}
        foreach($element in $list)
        {
            $dictionary.Add($element.FilePath,$element.Counter) 
        }
        $dictionary.GetEnumerator() | sort Value -Descending
    }
    else
    {
        "Probably you dont have logs for Applocker"
    }

    
   
    
}
Get-ApplockerListofApps