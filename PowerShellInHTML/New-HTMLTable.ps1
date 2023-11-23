# @IN: PSCustomObject with Get-ComputerInfo information
# @ACTION: creating table in HTML language
# @OUT: HTML code with @IN information
function New-HTMLTable() {

    [CmdletBinding()]
    param (
        [Parameter(HelpMessage = "Table content,Position=0")]
        [Alias("TableContent", "TC")]
        $content
    )
    $output = "<table class=`&quot w3-table-all w3-bordered w3-striped w3-border w3-hoverable `&quot><tr class=w3-green><td>KEY</td><td>VALUE</td></tr>"
    $content.PSObject.Properties | ForEach-Object { 
        $output += "<tr><td>$($_.Name)</td><td>$($_.Value)</td></tr>"
    }
    $output += "</table>"
    return $output
}