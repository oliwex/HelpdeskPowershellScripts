function counting()
{
    $today=(GET-DATE)
    $retireDate=”28/03/2060 10:00”
    $remainingWorkTime=NEW-TIMESPAN –Start $today –End $retireDate | SELECT Days,Hours,Minutes,Seconds
    return $remainingWorkTime
}
$time=counting
$userData=Get-ADUser -Identity $env:UserName | Select -ExpandProperty Name

function randomChuckNorrisJoke()
{
    $chuckNorrisJoke=Invoke-RestMethod -Uri https://api.chucknorris.io/jokes/random | Select -ExpandProperty value

    # ClientId and ClientSecretCode
    $clientId = "FREE_TRIAL_ACCOUNT"
    $clientSecret = "PUBLIC_SECRET"
    # Parameters to translate
    $nativeJokeLanguage = "en"
    $resultLanguage = "pl"
    #creating json object
    $jsonObj = @{'fromLang'=$nativeJokeLanguage;
                 'toLang'=$resultLanguage;
                 'text'=$chuckNorrisJoke;}

    #sending response into website
    $response = Invoke-WebRequest -Uri 'http://api.whatsmate.net/v1/translation/translate' `
                              -Method Post   `
                              -Headers @{"X-WM-CLIENT-ID"=$clientId; "X-WM-CLIENT-SECRET"=$clientSecret;} `
                              -Body (ConvertTo-Json $jsonObj)

    #writing joke on screen
    return $response.Content
}
$joke=randomChuckNorrisJoke

$text="DZIEN DOBRY $userData zostało ci $($time.Days) dni $($time.Hours) godzin $($time.Minutes) minut $($time.Seconds) sekund do emerytury, a teraz powiem żart: $($joke)"

$text
function sayText($text)
{
    Add-Type -AssemblyName System.speech
    $speak = New-Object System.Speech.Synthesis.SpeechSynthesizer
    $speak.Speak($text) 
}

sayText($text)