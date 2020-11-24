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
#######

function Get-ComputerReport 
{
    $computerReport = [ordered]@{
        "Disk"            = Get-Disk | Where-Object {$_.Number -eq 0 } | Select-Object FriendlyName, @{Name = "Size"; Expression = { (($_.Size)/1GB), "GB" -join " "} }
        "Processor"       = Get-CimInstance -Class Win32_Processor | Select-Object Name, @{Name = "TDP"; Expression = { $_.MaxClockSpeed } }
        "Memory"          = Get-CimInstance Win32_ComputerSystem | Select-Object @{Name="RAM";Expression={ [MATH]::Round(($_.TotalPhysicalMemory / 1GB),2), "GB" -join " "}}
        "VideoController" = Get-CimInstance Win32_VideoController | Where-Object { $_.DeviceId -eq "VideoController1" } | Select-Object Name, @{Name = "RAM"; Expression = { ($_.AdapterRam / 1GB), "GB" -join " " } }
    }

    return $computerReport
}
#######
$reportTitle="<h1>Computer name: HOST1</h1>"

$computerReport=$(Get-ComputerReport)
$disk=$computerReport.Disk | ConvertTo-Html -As List -Fragment -PreContent "<h2>DiskInfo</h2>"
$processor=$computerReport.Processor | ConvertTo-Html -As List -Fragment -PreContent "<h2>Processor</h2>"
$memory=$computerReport.Memory | ConvertTo-Html -As List -Fragment -PreContent "<h2>Memory</h2>"
$videoController=$computerReport.VideoController | ConvertTo-Html -As List -Fragment -PreContent "<h2>VideoController</h2>"

$Report = ConvertTo-HTML -Head $header -Body "<div class='hardware'>$disk $processor $memory $videoController</div>" -Title "Computer Information Report" -PostContent "<p id='CreationDate'>Creation Date: $(Get-Date)</p>"

#The command below will generate the report to an HTML file
$Report | Out-File .\\Basic-Computer-Information-Report.html