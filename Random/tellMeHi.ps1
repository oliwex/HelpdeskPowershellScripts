if ((Get-Service AudioSrv).Status -like "*Running*")
{
Add-Type -AssemblyName System.speech
$speak = New-Object System.Speech.Synthesis.SpeechSynthesizer
$speak.Speak('Hi guys') 
}
else
{
    "ERROR"
}

