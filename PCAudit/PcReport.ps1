function New-CSSStyles()
{
$styles=@"
    <style>
    h2
    {
        text-align: center;
    }
    body
    {
        margin: 0 auto;
        width: 90%;
    }
    .accordion 
    {
        background-color: #eee;
        color: #444;
        cursor: pointer;
        padding: 10px;
        width: 100%;
        border: none;
        text-align: left;
        font-size: 15px;
        transition: 0.4s;
    }
    .active, .accordion:hover 
    {
        background-color: #ccc;
    }
    .accordion:after 
    {
        content: '\002B';
        color: #777;
        font-weight: bold;
        float: right;
        margin-left: 5px;
    }
    .active:after 
    {
        content: "\2212";
    }
    .panel 
    {
        padding: 0 18px;
        background-color: white;
        max-height: 0;
        overflow: hidden;
        transition: max-height 0.2s ease-out;
    }
    </style>
"@
return $styles
}

function New-JSScript()
{
$script=@"
    <script>
    var acc = document.getElementsByClassName("accordion");
    var i;
    for (i = 0; i < acc.length; i++) 
    {
        acc[i].addEventListener("click", function() 
        {
            this.classList.toggle("active");
            var panel = this.nextElementSibling;
            if (panel.style.maxHeight) 
            {
                panel.style.maxHeight = null;
            } 
            else 
            {
                panel.style.maxHeight = panel.scrollHeight + "px";
            } 
        });
    }
    </script>
"@
return $script
}

function New-HTMLTitle()
{
    [CmdletBinding()]
    param (
    [Parameter(HelpMessage="Title of report expected,Position=0")]
    [Alias("MachineName","MN")]
    [String]$computerName=$($env:COMPUTERNAME)
    )

$title=@"
    <h2>$computerName</h2>
    <p>In this example we have added a "plus" sign to each button. When the user clicks on the button, the "plus" sign is replaced with a "minus" sign.</p>
"@
return $title
}

function New-HTMLAccordion()
{
    [CmdletBinding()]
    param (
    [Parameter(HelpMessage="Title,Position=0")]
    [Alias("Title","T")]
    [String]$accordionTitle
    )
$accordion=@"
    <button class="accordion">$accordionTitle</button>
        <div class="panel">
        <p>Lorem ipsum dolor sit amet, consectetur adipisicing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat.</p>
    </div>
"@
return $accordion
}

function New-HTMLReport()
{
$report=@"
    <!DOCTYPE html>
    <html>
    <head>
        <meta name="viewport" content="width=device-width, initial-scale=1">
        $(New-CSSStyles)
        </head>
    <body>

    $(New-HTMLTitle)

    $(New-HTMLAccordion -Title "LAMA")


    $(New-JSScript)
    </body>
    </html>
"@
return $report
}

New-HTMLReport | Out-File "lama.html"