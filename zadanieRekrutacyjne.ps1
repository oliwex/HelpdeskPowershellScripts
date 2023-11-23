<#
Zadanie rekrutacyjne z filmu Joma Tech na youtube
#>

$a=0 #wewnatrz koła
$b=0 #wewnatrz kwadratu
$sx=0
$sy=0

1..100000 | ForEach-Object {

$x=Get-Random -Minimum 0.0 -Maximum 1.0
$y=Get-Random -Minimum 0.0 -Maximum 1.0
$d=[Math]::Sqrt((($sx - $x)*($sx - $x))+(($sy - $y)*($sy - $y)))
if ($d -le 1)
{
$a++
}
$b++
}

$pi=4*($a/$b)
$pi

