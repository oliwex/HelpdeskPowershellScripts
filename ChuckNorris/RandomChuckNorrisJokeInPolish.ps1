﻿$chuckNorrisJoke=Invoke-RestMethod -Uri https://api.chucknorris.io/jokes/random | Select -ExpandProperty value

# ClientId and ClientSecretCode
$clientId = "FREE_TRIAL_ACCOUNT"
$clientSecret = "PUBLIC_SECRET"

$nativeJokeLanguage = "en"
$resultLanguage = "pl"

             'toLang'=$resultLanguage;
             'text'=$chuckNorrisJoke;}

#sending response into website
$response = Invoke-WebRequest -Uri 'http://api.whatsmate.net/v1/translation/translate' `
                          -Method Post   `
                          -Headers @{"X-WM-CLIENT-ID"=$clientId; "X-WM-CLIENT-SECRET"=$clientSecret;} `
                          -Body (ConvertTo-Json $jsonObj)

#writing joke on screen
Write-host $response.Content


#sending mail to user

Send-MailMessage -From 'you@gmail.com' -To 'yourboss@gmail.com' -Subject $response.Content