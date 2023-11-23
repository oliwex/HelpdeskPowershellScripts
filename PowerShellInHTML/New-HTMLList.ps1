# @IN: PSCustomObject with Get-ComputerInfo information
# @ACTION: creating list in HTML language
# @OUT: HTML code with @IN information
function New-HTMLList() {
    [CmdletBinding()]
    param (
        [Parameter(HelpMessage = "List Content,Position=0")]
        [Alias("ListContent", "LC")]
        $content
    )

    $output = "<ul class=`&quot w3-ul `&quot>"
    $content | ForEach-Object {
        $output += "<li>$($_)</li>"
    }
    $output += "</ul>"
    return $output
}