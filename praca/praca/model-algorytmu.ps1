$gpoLast=Get-ADOrganizationalUnit -Filter {name -eq "KOMPUTERY"} | Select-Object -ExpandProperty distinguishedname | Get-GPInheritance | Select-Object -ExpandProperty gpolinks | ForEach-Object {Get-GPO -Guid $_.gpoid} | Select-Object DisplayName,Id,ModificationTime



while($true)
{
Read-Host -Prompt "Zmiana w AD"
$testLastNull=[string]::IsNullOrEmpty($gpoLast)
$gpoCurrent=Get-ADOrganizationalUnit -Filter {name -eq "KOMPUTERY"} | Select-Object -ExpandProperty distinguishedname | Get-GPInheritance | Select-Object -ExpandProperty gpolinks | ForEach-Object {Get-GPO -Guid $_.gpoid} | Select-Object DisplayName,Id,ModificationTime
$testCurrentNull=[string]::IsNullOrEmpty($gpoCurrent)
if (($testLastNull -eq $true) -and ($testCurrentNull -eq $true))
{
    "Brak polityk w obu przypadkach"
}
if (($testLastNull -eq $false) -and ($testCurrentNull -eq $true))
{
    "1=POLITYKA,2=NULL"
}
if (($testLastNull -eq $true) -and ($testCurrentNull -eq $false))
{
    "1=NULL,2=POLITYKA"
}
if (($testLastNull -eq $false) -and ($testCurrentNull -eq $false))
{
    "1=POLITYKA,2=POLITYKA"
    $testCompare=Compare-Object -Property DisplayName,Id,ModificationTime -ReferenceObject $gpoLast -DifferenceObject $gpoCurrent
    $testExistence=[string]::IsNullOrEmpty($testCompare)
    if ($testExistence -eq $false)
    {
        "POLITYKI ISTNIEJĄ I ZOSTAŁY WYKONANE ZMIANY"

    }
}

$gpoLast=$gpoCurrent
Start-Sleep -Seconds 5
}

