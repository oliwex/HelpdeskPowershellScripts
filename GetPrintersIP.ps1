﻿Get-Printer -ComputerName <server> | Select -ExpandProperty Name | foreach { [System.Net.Dns]::GetHostEntry($_) }