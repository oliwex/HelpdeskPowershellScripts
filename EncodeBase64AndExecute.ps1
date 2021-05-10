$string = 'Get-Service'

$encodedcommand = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($string))
$encodedcommand
powershell.exe -EncodedCommand "RwBlAHQALQBTAGUAcgB2AGkAYwBlAA=="