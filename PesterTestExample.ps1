BeforeAll { 
    function Get-Planet ([string]$Name = '*') {
        $planets = @(
            @{ Name = 'Mercury' }
            @{ Name = 'Venus'   }
            @{ Name = 'Earth'   }
            @{ Name = 'Mars'    }
            @{ Name = 'Jupiter' }
            @{ Name = 'Saturn'  }
            @{ Name = 'Uranus'  }
            @{ Name = 'Neptune' }
        ) | ForEach-Object { [PSCustomObject] $_ }

        $planets | Where-Object { $_.Name -like $Name }
    }
}
Describe 'Get-Planet' {
    It 'Given no parameters, it lists all 8 planets' {
        $allPlanets = Get-Planet
        $allPlanets.Count | Should -Be 8
    }
    It 'Given filter on Mars, Mars is given' {
        $allPlanets = Get-Planet
        ($allPlanets | Where-Object {$_.Name -like "Mars"}).Name | Should -Be "Mars" -Because 'It is good test result'
    }
    It 'Given wrong filter, returns false'{
        $allPlanets = Get-Planet
        ($allPlanets | Where-Object {$_.Name -like "Pluton"}).Name | Should -BeFalse -Because 'The planet is not exists'
    }
}
