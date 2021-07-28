
$groupObject1 = [PsCustomObject] @{
    "DomainLocal"     = $groups | Where-Object { $_.GroupScope -like "DomainLocal" } | Group-Object GroupCategory | Select-Object Name, Count  
    "Universal" = $groups | Where-Object { $_.GroupScope -like "Universal" } | Group-Object GroupCategory | Select-Object Name, Count
    "Global" = $groups | Where-Object { $_.GroupScope -like "Global" } | Group-Object GroupCategory | Select-Object Name, Count
}

$FilePath = "C:\Users\moliwinski\PSWriteWord-Example-Tables5.docx"

$myitems = @(
    [pscustomobject]@{GroupName = "DomainLocal"; Security = $($groupObject1.DomainLocal[1]).Count; Distribution = $($groupObject1.DomainLocal[1]).Count},
    [pscustomobject]@{GroupName = "Universal"; Security = $($groupObject1.Universal[0]).Count; Distribution = $($groupObject1.Universal[1]).Count},
    [pscustomobject]@{GroupName = "Global"; Security = $($groupObject1.Global[0]).Count; Distribution = $($groupObject1.Global[1]).Count}
)


$WordDocument = New-WordDocument $FilePath

Add-WordTable -WordDocument $WordDocument -DataTable $myitems -Design ColorfulGridAccent1 -Supress $True #-Verbose

Save-WordDocument $WordDocument -Language 'en-US' -Supress $True

### Start Word with file
Invoke-Item $FilePath