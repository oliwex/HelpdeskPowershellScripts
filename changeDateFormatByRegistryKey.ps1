Invoke-Command -ComputerName Pc1 {
New-PSDrive -PSProvider Registry -Name HKU -Root HKEY_USERS
Set-ItemProperty -Path "HKU:\.DEFAULT\Control Panel\International" -Name "sShortDate" -Value "yyyy-mm-dd"
Remove-PsDrive -Name HKU
}