﻿Get-WmiObject -Class Win32_UserProfile -ComputerName "computer" | Where-Object {($_.Loaded -eq $true) -AND ($_.LocalPath -like "C:\Users\*")}