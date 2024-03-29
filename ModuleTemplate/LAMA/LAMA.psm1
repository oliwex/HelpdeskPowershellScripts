# Implement your module commands in this script.


# Export only the functions using PowerShell standard verb-noun naming.
# Be sure to list each exported functions in the FunctionsToExport field of the module manifest file.
# This improves performance of command discovery in PowerShell.
#Export-ModuleMember -Function Get-Lama

Get-ChildItem -Path "$PSScriptRoot/Public", "$PSScriptRoot/Private" -File -Recurse *.ps1 | ForEach-Object {
    . $_.FullName
}
