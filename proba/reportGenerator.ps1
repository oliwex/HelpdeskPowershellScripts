


######################################################

$filePath = "C:\reporty\report.docx"
$reportFile = New-WordDocument $filePath

Add-WordText -WordDocument $reportFile -Text 'Raport z Active Directory' -FontSize 28 -FontFamily 'Calibri Light' -Supress $True
Add-WordPageBreak -WordDocument $reportFile -Supress $true

Add-WordTOC -WordDocument $reportFile -Title 'Spis treści' -HeaderStyle Heading1 -Supress $true
Add-WordPageBreak -WordDocument $reportFile -Supress $true

Add-WordTocItem -WordDocument $reportFile -ListLevel 1 -ListItemType Numbered -HeadingType Heading1 -Text 'Wstęp' -Supress $true
Add-WordText -WordDocument $reportFile -Text 'Jest to dokumentacja domeny ActiveDirectory przeprowadzona w domena.local. Wszytskie informacje są tajne' -Supress $True

Add-WordTocItem -WordDocument $reportFile -ListLevel 1 -ListItemType Numbered -HeadingType Heading1 -Text 'Spis jednostek organizacyjnych' -Supress $true
Add-WordText -WordDocument $reportFile -Text 'Ta część zawiera spis jednostek organizacyjnych wraz z informacjami o każdej z nich' -Supress $True

$ous=(Get-ADOrganizationalUnit -Filter "*").DistinguishedName
foreach($ou in $ous)
{
    Add-WordTocItem -WordDocument $reportFile -ListLevel 2 -ListItemType Numbered -HeadingType Heading1 -Text "$ou" -Supress $true
    Add-WordTable -WordDocument $reportFile -DataTable $(Get-OUInformation -OU $ou -Extended:$true) -Design ColorfulGridAccent5 -AutoFit Window -OverwriteTitle $ou -Transpose -Supress $True
}
    <#
    #OU
    #DONE


        foreach($ou in $ous)
        {
            DocNumbering -Text $ou -Level 1 -Type Numbered -Heading Heading1 {
            DocTable -DataTable $(Get-OUInformation -OU $ou -Extended:$true) -Design ColorfulGridAccent5 -AutoFit Window -OverwriteTitle $ou -Transpose          
            DocText -LineBreak
                DocNumbering -Text "'$ou' Permission" -Level 2 -Type Bulleted -Heading Heading1 {
                DocTable -DataTable $($(Get-OUACL -OU $ou) | Select-Object -Property * -ExcludeProperty ACLs) -Design ColorfulGridAccent5 -AutoFit Window -OverwriteTitle "OU Options" -Transpose
                DocText -LineBreak
                    $(Get-OUACL -ouPath $ou).ACLs | ForEach-Object {
                    DocTable -DataTable $($_) -Design ColorfulGridAccent5 -AutoFit Window -OverwriteTitle "Permissions" -Transpose
                    DocText -LineBreak
                    }
                DocText -LineBreak
                }
            }
        }
        DocText -LineBreak
    }
    #>

Save-WordDocument $reportFile -Supress $true -Language 'en-US' -Verbose #-OpenDocument