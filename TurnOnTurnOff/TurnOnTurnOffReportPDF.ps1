$element=Get-WinEvent -FilterHashTable @{ ProviderName = 'Microsoft-Windows-Power-TroubleShooter'  ; Id = 1 }|Select-Object -Property @{n='Sleep';e={Get-Date -Date $($_.Properties[0].Value) -Format "dd-MM-yyyy @ hh:mm:ss"}},@{n='Wake';e={Get-Date -Date $($_.Properties[1].Value) -Format "dd-MM-yyyy @ hh:mm:ss"}}

$DataTable2 = @(
    $element
)

New-PDF {

    New-PDFText -Text 'Turn on and Turn off computer' -Font HELVETICA -FontColor RED

    New-PDFTable -DataTable $DataTable2

} -FilePath "F:\GIT\HelpdeskPowershellScripts\Random\Example06.pdf" -Show