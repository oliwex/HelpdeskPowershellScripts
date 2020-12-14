param($fullReport,$computerToMonitor,$resultFile)
#############################################################################################
#############################################################################################
#############################################################################################
$style = @"
<head>
<style>

	body
	{
		margin: 0 auto;
		width:80%
	}
    .report
    {
        text-align: center;
    }
    h1 
    {
		text-align: center;
        font-family: Calibri;
        color: #015965;
        font-size: 28px;
    }
    h2 
	{
        font-family: 'Lato', sans-serif;
        color: #009999;
        font-size: 20px;
		text-align:center;
    }
	.hardware > table , .software > table , .fileshare > table , .service > table , .firewall > table
	{
		display:inline;
	}
    .quota > table , .network > table, .printer > table , .defender > table
	{
		margin:0 auto;
	}
    
   table 
   {
		font-size: 12px;
		font-family: Arial, Helvetica, sans-serif;
        text-align: left;
	} 
    td 
    {
		padding: 4px;
		margin: 0px;
		border: 0;
	}
    th 
    {
        background: #395870;
        background: linear-gradient(#49708f, #293f50);
        color: #fff;
        font-size: 11px;
        text-transform: uppercase;
        padding: 10px 15px;
        vertical-align: middle;
	}

    tbody tr:nth-child(even) 
    {
        background: #f0f0f2;
    }

    .changed {

        color: #FF0000;
    }
    
    .notchanged {

        color: #00FF00;
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
    [Parameter(Mandatory=$true,HelpMessage="ReportElement",Position=0)]
    $reportElement,

    [Parameter(Mandatory=$true,HelpMessage="HashtableFlag",Position=1)]
    $hashtableFlag
    )

    if (!($hashtableFlag))
    {
        $element=[PSCustomObject]$reportElement | ConvertTo-Html -As Table -Fragment
        $element = $element -replace '<td>NOTCHANGED</td>','<td class="notchanged">NOTCHANGED</td>'
        $element = $element -replace '<td>CHANGED</td>','<td class="changed">CHANGED</td>'
    }
    else
    {
        $element="<table><tr><th>ELEMENT</th><th>CURRENT_STATE</th></tr>"
        if ($reportElement.GetType().Name -eq "Hashtable")
        {
            $tableBody=$($reportElement.Keys) | ForEach-Object { "<tr><td>$_</td><td>$($reportElement[$_])</td></tr>"}
        }
        else
        {
            $tableBody=$($reportElement.Keys) | ForEach-Object { "<tr><td>$_</td><td>$($reportElement.$_)</td></tr>"}
        }
        $element=$element+$tableBody+"</table>"
    }
    return $element
}


####################################################################################################
####################################################################################################
####################################################################################################

$reportTitle="<h1>Computer name: $computerToMonitor</h1>"

#HARDWARE
$hardwareReportTitle="<h2>Hardware Report</h2>"
$disk=New-ReportElement -reportElement $($($fullReport.HARDWARE).Disk) -hashtableFlag $($fullReport.FIRST)
$processor=New-ReportElement -reportElement $($($fullReport.HARDWARE).Processor) -hashtableFlag $($fullReport.FIRST)
$memory=New-ReportElement -reportElement $($($fullReport.HARDWARE).Memory) -hashtableFlag $($fullReport.FIRST)
$videoController=New-ReportElement -reportElement $($($fullReport.HARDWARE).VideoController) -hashtableFlag $($fullReport.FIRST)
$hardwareReport = ConvertTo-HTML -Body "<div class='hardware'>$hardwareReportTitle $disk $processor $memory $videoController</div>"


#QUOTA
$quotaReportTitle="<h2>Quota Report</h2>"
$quota=New-ReportElement -reportElement $($fullReport.QUOTA) -hashtableFlag $($fullReport.FIRST)
$quotaReport = ConvertTo-HTML -Body "<div class='quota'>$quotaReportTitle $quota</div>"


#SOFTWARE
$softwareReportTitle="<h2>Software Report</h2>"
$adobe=New-ReportElement -reportElement $($($fullReport.SOFTWARE).Adobe) -hashtableFlag $($fullReport.FIRST)
$java=New-ReportElement -reportElement $($($fullReport.SOFTWARE)."Java 8") -hashtableFlag $($fullReport.FIRST)
$zip=New-ReportElement -reportElement $($($fullReport.SOFTWARE)."7-zip") -hashtableFlag $($fullReport.FIRST)
$notepad=New-ReportElement -reportElement $($($fullReport.SOFTWARE)."Notepad++") -hashtableFlag $($fullReport.FIRST)
$edge=New-ReportElement -reportElement $($($fullReport.SOFTWARE)."Microsoft Edge") -hashtableFlag $($fullReport.FIRST)
$softwareReport = ConvertTo-HTML -Body "<div class='software'>$softwareReportTitle $adobe $java $zip $notepad $edge</div>" 

#FILESHARE
$fileshareReportTitle="<h2>Fileshare Report</h2>"
$userFolderUserAccess=New-ReportElement -reportElement $($($fullReport.FILESHARE).UserFolderUserAccess) -hashtableFlag $($fullReport.FIRST)
$departmentFolderGroupAccess=New-ReportElement -reportElement $($($fullReport.FILESHARE).DepartmentFolderGroupAccess) -hashtableFlag $($fullReport.FIRST)
$userFolderGroupAccess=New-ReportElement -reportElement $($($fullReport.FILESHARE).UserFolderGroupAccess) -hashtableFlag $($fullReport.FIRST)
$departmentFolderUserAccess=New-ReportElement -reportElement $($($fullReport.FILESHARE).DepartmentFolderUserAccess) -hashtableFlag $($fullReport.FIRST)
$fileshareReport = ConvertTo-HTML -Body "<div class='fileshare'>$fileshareReportTitle $userFolderUserAccess $departmentFolderGroupAccess $userFolderGroupAccess $departmentFolderUserAccess</div>" 

#NETWORK
$networkReportTitle="<h2>Network Report</h2>"
$network=New-ReportElement -reportElement $($fullReport.NETWORK) -hashtableFlag $($fullReport.FIRST)
$networkReport = ConvertTo-HTML -Body "<div class='network'>$networkReportTitle $network</div>"

#PRINTER
$printerReportTitle="<h2>Printer Report</h2>"
$printer=New-ReportElement -reportElement $($fullReport.PRINTER) -hashtableFlag $($fullReport.FIRST)
$printerReport = ConvertTo-HTML -Body "<div class='printer'>$printerReportTitle $printer</div>"

#SERVICE
$serviceReportTitle="<h2>Service Report</h2>"
$AppIDSvc=New-ReportElement -reportElement $($($fullReport.SERVICE).AppIDSvc) -hashtableFlag $($fullReport.FIRST)
$mpssvc=New-ReportElement -reportElement $($($fullReport.SERVICE).mpssvc) -hashtableFlag $($fullReport.FIRST)
$W32Time=New-ReportElement -reportElement $($($fullReport.SERVICE).W32Time) -hashtableFlag $($fullReport.FIRST)
$WinDefend=New-ReportElement -reportElement $($($fullReport.SERVICE).WinDefend) -hashtableFlag $($fullReport.FIRST)
$wuauserv=New-ReportElement -reportElement $($($fullReport.SERVICE).wuauserv) -hashtableFlag $($fullReport.FIRST)
$serviceReport = ConvertTo-HTML -Body "<div class='service'>$serviceReportTitle $AppIDSvc $mpssvc $W32Time $WinDefend $wuauserv</div>"  

#FIREWALL
$firewallReportTitle="<h2>Firewall Report</h2>"
$domain=New-ReportElement -reportElement $($($fullReport.FIREWALL).Domain) -hashtableFlag $($fullReport.FIRST)
$private=New-ReportElement -reportElement $($($fullReport.FIREWALL).Private) -hashtableFlag $($fullReport.FIRST)
$public=New-ReportElement -reportElement $($($fullReport.FIREWALL).Public) -hashtableFlag $($fullReport.FIRST)
$firewallReport = ConvertTo-HTML -Body "<div class='firewall'>$firewallReportTitle $domain $private $public</div>"  

#DEFENDER
$defenderReportTitle="<h2>Defender Report</h2>"
$defender=New-ReportElement -reportElement $($fullReport.DEFENDER) -hashtableFlag $($fullReport.FIRST)
$defenderReport = ConvertTo-HTML -Body "<div class='defender'>$defenderReportTitle $defender</div>"


#MERGE 
$report = ConvertTo-HTML -Head $style -Body "<div class='report'>$reportTitle $hardwareReport $quotaReport$softwareReport $fileshareReport $networkReport $printerReport $serviceReport $firewallReport $defenderReport</div>"  
$report | Out-File -FilePath $resultFile
