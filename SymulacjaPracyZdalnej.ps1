Add-Type -AssemblyName System.Windows.Forms
$myshell = New-Object -com "Wscript.Shell"

while ($true) 
{
    $MOVE=Get-Random -Minimum 0 -Maximum 100
    $myshell.sendkeys(".")

    $POSITION = [Windows.Forms.Cursor]::Position
    $POSITION.x += $MOVE
    $POSITION.y += $MOVE
    Start-Sleep -Seconds 5
}
