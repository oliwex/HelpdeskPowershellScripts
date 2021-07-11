#Local security groups - tworzone gdy tworzy się AD
#Get-ADGroup -Filter {GroupType -eq -2147483643} | Select-Object Name | Sort-Object Name
Get-ADGroup -Filter {GroupType -band 1} -Properties Name,GroupType | Select-Object Name,GroupType

#category = security/distribution
#scope=universal/global/domain_local
#builtin=tworzone przy starcie AD