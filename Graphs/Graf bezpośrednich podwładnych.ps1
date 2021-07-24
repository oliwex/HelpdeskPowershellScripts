


function Get-GraphOfDirectReports($boss)
{
    $pathToTemplateFile="C:\hello.vz"
    $pathToResultFileFile="C:\hello.png"

    $listofEmployees = @((Get-ADUser -Identity $boss -Properties directreports | Select-Object -ExpandProperty directreports | Get-ADUser -Properties mail).SamAccountName)

    $dependencyGraph=graph g {
        edge -From $boss -To $listofEmployees
    }


    Set-Content -Path C:\hello.vz -Value $dependencyGraph

    Export-PSGraph -Source C:\hello.vz -Destination C:\hello.png

}

Get-GraphOfDirectReports cnita