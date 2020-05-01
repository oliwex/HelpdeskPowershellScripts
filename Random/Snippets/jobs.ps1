Start-Job –Name GetFileList –Scriptblock {Get-Process}

$result = (Get-Job –Name GetFileList | Wait-Job | Receive-Job )

$result