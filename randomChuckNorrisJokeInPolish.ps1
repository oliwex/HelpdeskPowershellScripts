$chuckNorrisJoke=Invoke-RestMethod -Uri https://api.chucknorris.io/jokes/random | Select -ExpandProperty value

# ClientId and ClientSecretCode
$clientId = "FREE_TRIAL_ACCOUNT"
$clientSecret = "PUBLIC_SECRET"
# Parameters to translate
$nativeJokeLanguage = "en"
$resultLanguage = "pl"
#creating json object$jsonObj = @{'fromLang'=$nativeJokeLanguage;
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

Send-MailMessage -From 'yourboss@gmail.com' -To 'yourboss@gmail.com' -Subject $response.Content
