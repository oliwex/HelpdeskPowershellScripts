Get-ADComputer -Filter 'operatingsystem -like "*Windows 10*"' -Properties  Name, OperatingSystemVersion | Select-Object -Property Name, OperatingSystemVersion |
group {
switch -regex ($_.OperatingSystemVersion) {
"19042" {"20.09";continue}
"19041" {"20.03";continue}
"18363" {"19.09";continue}
"18362" {"19.03";continue}
Default {"OLD"}
}
}| Select-Object Count,Name | Sort-Object -Property @{Expression = "Name"; Descending = $false}