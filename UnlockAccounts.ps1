$userLogin=Read-Host "Give me login: "
$check=Get-AdUser -Identity $userLogin -Properties LockedOut | Select -ExpandProperty LockedOut
if ($check -eq $true)
{
    "Account is locked"
    Unlock-ADAccount -Identity $userLogin -Credential (Get-Credential)
    "Account is unlocked"
}
else
{
    "Account is not lock"
    Clear-Host
    
}
"Press Enter..."
Read-Host