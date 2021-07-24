$path="C:\test\"

$groups=(Get-ADGroup  -Filter '*' | Select -ExpandProperty Name)
foreach($group in $groups)
{
    $members=(Get-ADGroupMember $group | Select name)
    if ($members -eq $null)
    {
        continue
    }
    else
    {
        $graph = graph g {
        $members | %{edge -from $group -to $_.Name}
        }
    }
    
    $filePath=$path+$group
    Set-Content -Path $filePath+".vz" -Value $graph
    Export-PSGraph -Source $filePath+".vz" -Destination $filePath+".png" -ShowGraph
    Remove-Item $filePath+".vz"
}
