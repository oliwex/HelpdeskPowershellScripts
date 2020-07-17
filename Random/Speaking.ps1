function sayText($text)
{
    Add-Type -AssemblyName System.speech
    $speak = New-Object System.Speech.Synthesis.SpeechSynthesizer
    $speak.Speak($text) 
}
sayText("Dowidzenia, miłego popołudnia")
