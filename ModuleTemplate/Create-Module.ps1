Install-Module InvokeBuild
Install-Module PowerShellGet
Install-Module ModuleBuilder
Install-Module Pester

$defaultTemplate = Get-PlasterTemplate | Where-Object -FilterScript {$PSItem.Title -eq 'New PowerShell Manifest Module'}
Invoke-Plaster -TemplatePath $defaultTemplate.TemplatePath -DestinationPath .  -Verbose