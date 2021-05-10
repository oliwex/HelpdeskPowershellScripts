Add-Type -AssemblyName System.web
[System.Web.Security.Membership]::GeneratePassword(10,0)