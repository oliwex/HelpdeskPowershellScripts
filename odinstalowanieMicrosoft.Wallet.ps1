Get-AppxPackage -Name "Microsoft.Wallet" -AllUsers | Remove-AppxPackage -AllUsers

Get-AppXProvisionedPackage -Online | Where-Object DisplayName -EQ "Microsoft.Wallet" | Remove-AppxProvisionedPackage -Online
# Cleanup Local App Data
$appPath="$Env:LOCALAPPDATA\Packages\Microsoft.Wallet*"
Remove-Item $appPath -Recurse -Force -ErrorAction 0