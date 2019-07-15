$userLogin=Read-Host "Give me login: "
$var=Get-AdUser -Identity $userLogin -Properties LockedOut | Select LockedOut
if ($var -eq $true)
{
Unlock-ADAccount -Identity $userLogin
"Account is blocked"
Read-Host
}
else
{
Clear-Host
"Account is not blocked"
Read-Host

}
