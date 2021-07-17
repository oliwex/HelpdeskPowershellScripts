#Local security groups - tworzone gdy tworzy się AD
#Get-ADGroup -Filter {GroupType -eq -2147483643} | Select-Object Name | Sort-Object Name
Get-ADGroup -Filter {GroupType -band 1} -Properties Name,GroupType | Select-Object Name,GroupType

#category = security/distribution
#scope=universal/global/domain_local
#builtin=tworzone przy starcie AD



#TODO:graph with group difference
function Get-AdGroupDiff
{
Param(
     [Parameter(Mandatory=$true)]
     [alias("GroupTypeDiff")]
     [ValidateSet("SystemGroupsScope","GlobalScope","DomainLocalScope","UniversalScope","DistributionGroups")]
     $groupType
 )

 $filter=$null
if ($groupType -eq "SystemGroupsScope")
{
$filter="{GroupType -band 1}"
}
elseif($groupType -eq "GlobalScope")
{
$filter={GroupType -band 2}
}
elseif($groupType -eq "DomainLocalScope")
{
$filter={GroupType -band 4}
}
elseif($groupType -eq "UniversalScope")
{
$filter={GroupType -band 8}
}
elseif($groupType -eq "DistributionGroups")
{
$filter={-not(GroupType -band 8)}
}
Get-ADGroup -Filter $filter -Properties Name,GroupType | Select-Object Name,GroupType
}


Get-ADGroupDiff -GroupTypeDiff "UniversalScope"