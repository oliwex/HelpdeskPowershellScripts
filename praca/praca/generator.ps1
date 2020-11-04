#####################
#WSTEP
#$fullreport-hashtablea zawierajaca dane z systemu
#TODO:
#Zrobienie monitorowania pierwszego i kolejnych
#Wykonanie listy raportowej danych z full Report
#####################
param($fullReport)


$datetime=Get-Date -Format "HH:mm MM/dd/yyyy"

$WordDocument = New-WordDocument "C:\TEST\lama.docx"

Add-WordText -WordDocument $WordDocument -Text 'Raport monitorowania stacji roboczej' -FontSize 20 -Color Red -FontFamily HELVETICA -Alignment center 
Add-WordText -WordDocument $WordDocument -Text "Monitorowanie wykonano dnia: '$datetime'" -FontSize 15 -Color Blue -FontFamily HELVETICA -Alignment center

Add-WordParagraph -WordDocument $WordDocument -Supress $true # Empty Line


$fullReport



#Add-WordList -WordDocument $WordDocument -ListType Bulleted -ListData $fullReport.Keys -Supress $True -Verbose
#Add-WordParagraph -WordDocument $WordDocument -Supress $true # Empty Line

#region Main
#region HARDWARE
#$centerParagraph = Add-WordText -WordDocument $WordDocument -Text "HARDWARE" -FontSize 15 -Color Blue -FontFamily HELVETICA
#Set-WordParagraph -Paragraph $centerParagraph -Alignment center

#Add-WordTable -WordDocument $WordDocument -DataTable $($fullReport.HARDWARE.Disk) -Design LightShading

#Add-WordParagraph -WordDocument $WordDocument -Supress $True # Empty Line
    
#endregion HARDWARE
<#
#region QUTOA
$centerParagraph = Add-WordText -WordDocument $WordDocument -Text "QUOTA" -FontSize 15 -Color Blue -FontFamily HELVETICA

$centerParagraph = Add-WordTable -WordDocument $WordDocument -DataTable $fullReport.QUOTA -Design LightShading
Add-WordParagraph -WordDocument $WordDocument -Supress $True # Empty Line
Set-WordParagraph -Paragraph $centerParagraph -Alignment center

#endregion QUOTA

#region NETWORK
$centerParagraph = Add-WordText -WordDocument $WordDocument -Text "NETWORK" -FontSize 15 -Color Blue -FontFamily HELVETICA

$centerParagraph = Add-WordTable -WordDocument $WordDocument -DataTable $fullReport.NETWORK -Design LightShading
Add-WordParagraph -WordDocument $WordDocument -Supress $True # Empty Line
Set-WordParagraph -Paragraph $centerParagraph -Alignment center
#endregion NETWORK

#region PRINTER
$centerParagraph = Add-WordText -WordDocument $WordDocument -Text "PRINTER" -FontSize 15 -Color Blue -FontFamily HELVETICA

$centerParagraph = Add-WordTable -WordDocument $WordDocument -DataTable $fullReport.PRINTER -Design LightShading
Add-WordParagraph -WordDocument $WordDocument -Supress $True # Empty Line
Set-WordParagraph -Paragraph $centerParagraph -Alignment center
#endregion PRINTER

#region SERVICE
$centerParagraph = Add-WordText -WordDocument $WordDocument -Text "SERVICE" -FontSize 15 -Color Blue -FontFamily HELVETICA

foreach ($element in $fullReport.SERVICE.Keys)
{
    $centerParagraph = Add-WordTable -WordDocument $WordDocument -DataTable $fullReport.SERVICE.Keys -Design LightShading
    Add-WordParagraph -WordDocument $WordDocument -Supress $True # Empty Line
    Set-WordParagraph -Paragraph $centerParagraph -Alignment center
}
#endregion SERVICE

#region FIREWALL
$centerParagraph = Add-WordText -WordDocument $WordDocument -Text "FIREWALL" -FontSize 15 -Color Blue -FontFamily HELVETICA

foreach ($element in $fullReport.FIREWALL.Keys)
{
    $centerParagraph = Add-WordTable -WordDocument $WordDocument -DataTable $fullReport.FIREWALL.Keys -Design LightShading
    Add-WordParagraph -WordDocument $WordDocument -Supress $True # Empty Line
    Set-WordParagraph -Paragraph $centerParagraph -Alignment center
}
#endregion FIREWALL

#region DEFENDER
$centerParagraph = Add-WordTable -WordDocument $WordDocument -DataTable $fullReport.DEFENDER -Design LightShading
Add-WordParagraph -WordDocument $WordDocument -Supress $True # Empty Line
Set-WordParagraph -Paragraph $centerParagraph -Alignment center
#endregion DEFENDER

#region LOG
$centerParagraph = Add-WordText -WordDocument $WordDocument -Text "LOG" -FontSize 15 -Color Blue -FontFamily HELVETICA

foreach ($element in $fullReport.LOG.Keys)
{
    $centerParagraph = Add-WordTable -WordDocument $WordDocument -DataTable $fullReport.LOG.Keys -Design LightShading
    Add-WordParagraph -WordDocument $WordDocument -Supress $True # Empty Line
    Set-WordParagraph -Paragraph $centerParagraph -Alignment center
}
#endregion LOG

#endregion Main
#>
Save-WordDocument $WordDocument -Supress $True
