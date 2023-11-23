# @IN: NONE
# @ACTION: information about stylesheet
# @OUT: CSS code to inject into HTML file
function New-HTMLHead() {
    $head = @"
    <head>
        <title>W3.CSS</title>
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <link rel="stylesheet" href="https://www.w3schools.com/w3css/4/w3.css">
        <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/4.7.0/css/font-awesome.min.css">
        
"@
    return $head
}