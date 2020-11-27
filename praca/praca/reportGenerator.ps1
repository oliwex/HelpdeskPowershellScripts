#############################################################################################
#############################################################################################
#############################################################################################
$header = @"
<style>

    h1 {

        font-family: Arial, Helvetica, sans-serif;
        color: #e68a00;
        font-size: 28px;

    }

    
    h2 {

        font-family: Arial, Helvetica, sans-serif;
        color: #000099;
        font-size: 16px;

    }

    
    
   table {
		font-size: 12px;
		border: 0px; 
		font-family: Arial, Helvetica, sans-serif;
	} 
	
    td {
		padding: 4px;
		margin: 0px;
		border: 0;
	}
	
    th {
        background: #395870;
        background: linear-gradient(#49708f, #293f50);
        color: #fff;
        font-size: 11px;
        text-transform: uppercase;
        padding: 10px 15px;
        vertical-align: middle;
	}

    tbody tr:nth-child(even) {
        background: #f0f0f2;
    }
    


    #CreationDate {

        font-family: Arial, Helvetica, sans-serif;
        color: #ff3300;
        font-size: 12px;

    }



    .StopStatus {

        color: #ff0000;
    }
    
  
    .RunningStatus {

        color: #008000;
    }




</style>
"@
####################################################################################################
####################################################################################################
####################################################################################################
function New-ReportElement
{
    [CmdletBinding()]
    Param(
    [Parameter(Mandatory=$true,HelpMessage="ReportElement",Position=1)]
    $reportElement
    )
    $element=[PSCustomObject]$reportElement | ConvertTo-Html -As Table -Fragment
    return $element
}


####################################################################################################
####################################################################################################
####################################################################################################

$reportTitle="<h1>Computer name: $computerToMonitor</h1>"

#HARDWARE
$hardwareReportTitle="<h2>Hardware Report</h2>"
$disk=New-ReportElement -reportElement $($($fullReport.HARDWARE).Disk)
$processor=New-ReportElement -reportElement $($($fullReport.HARDWARE).Processor)
$memory=New-ReportElement -reportElement $($($fullReport.HARDWARE).Memory)
$videoController=New-ReportElement -reportElement $($($fullReport.HARDWARE).VideOController)
$hardwareReport = ConvertTo-HTML -Body "<div class='hardware'>$hardwareReportTitle $disk $processor $memory $videoController</div>"  


#QUOTA
$quotaReportTitle="<h2>Quota Report</h2>"
$quota=New-ReportElement -reportElement $($fullReport.QUOTA)
$quotaReport = ConvertTo-HTML -Body "<div class='quota'>$quotaReportTitle $quota</div>"


#SOFTWARE
$softwareReportTitle="<h2>Service Report</h2>"
$adobe=New-ReportElement -reportElement $($($fullReport.SOFTWARE).Adobe)
$java=New-ReportElement -reportElement $($($fullReport.SOFTWARE)."Java 8")
$zip=New-ReportElement -reportElement $($($fullReport.SOFTWARE)."7-zip")
$notepad=New-ReportElement -reportElement $($($fullReport.SOFTWARE)."Notepad++")
$edge=New-ReportElement -reportElement $($($fullReport.SOFTWARE)."Microsoft Edge")
$softwareReport = ConvertTo-HTML -Body "<div class='service'>$softwareReportTitle $adobe $java $zip $notepad $edge</div>" 

#FILESHARE
$fileshareReportTitle="<h2>Service Report</h2>"
$userFolderUserAccess=New-ReportElement -reportElement $($($fullReport.FILESHARE).UserFolderUserAccess)
$departmentFolderGroupAccess=New-ReportElement -reportElement $($($fullReport.FILESHARE).DepartmentFolderGroupAccess)
$userFolderGroupAccess=New-ReportElement -reportElement $($($fullReport.FILESHARE).UserFolderGroupAccess)
$departmentFolderUserAccess=New-ReportElement -reportElement $($($fullReport.FILESHARE).DepartmentFolderUserAccess)
$fileshareReport = ConvertTo-HTML -Body "<div class='service'>$fileshareReportTitle $userFolderUserAccess $departmentFolderGroupAccess $userFolderGroupAccess $departmentFolderUserAccess</div>" 

#NETWORK
$networkReportTitle="<h2>Network Report</h2>"
$network=New-ReportElement -reportElement $($fullReport.NETWORK)
$networkReport = ConvertTo-HTML -Body "<div class='network'>$networkReportTitle $network</div>"

#PRINTER
$printerReportTitle="<h2>Printer Report</h2>"
$printer=New-ReportElement -reportElement $($fullReport.PRINTER)
$printerReport = ConvertTo-HTML -Body "<div class='printer'>$printerReportTitle $printer</div>"

#SERVICE
$serviceReportTitle="<h2>Service Report</h2>"
$AppIDSvc=New-ReportElement -reportElement $($($fullReport.SERVICE).AppIDSvc)
$mpssvc=New-ReportElement -reportElement $($($fullReport.SERVICE).mpssvc)
$W32Time=New-ReportElement -reportElement $($($fullReport.SERVICE).W32Time)
$WinDefend=New-ReportElement -reportElement $($($fullReport.SERVICE).WinDefend)
$wuauserv=New-ReportElement -reportElement $($($fullReport.SERVICE).wuauserv)
$serviceReport = ConvertTo-HTML -Body "<div class='service'>$serviceReportTitle $AppIDSvc $mpssvc $W32Time $WinDefend $wuauserv</div>"  

#FIREWALL
$firewallReportTitle="<h2>Firewall Report</h2>"
$domain=New-ReportElement -reportElement $($($fullReport.FIREWALL).Domain)
$private=New-ReportElement -reportElement $($($fullReport.FIREWALL).Private)
$public=New-ReportElement -reportElement $($($fullReport.FIREWALL).Public)
$firewallReport = ConvertTo-HTML -Body "<div class='firewall'>$firewallReportTitle $domain $private $public</div>"  

#DEFENDER
$defenderReportTitle="<h2>Defender Report</h2>"
$defender=New-ReportElement -reportElement $($($fullReport.DEFENDER))
$defenderReport = ConvertTo-HTML -Body "<div class='defender'>$defenderReportTitle $defender</div>"


#MERGE
$report = ConvertTo-HTML -Head $header -Body "<div class='report'>$reportTitle $hardwareReport $quotaReport $networkReport $printerReport $serviceReport $firewallReport $defenderReport</div>"  
$report | Out-File C:\Basic-Computer-Information-Report.html


