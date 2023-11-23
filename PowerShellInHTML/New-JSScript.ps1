# @IN: NONE
# @ACTION: changing data in dashboard
# @OUT: Javascript code to inject into HTML file
function New-JSScript() {
    $script = @"
    <script>
    function changeContent(content) 
    {
        document.getElementById('lama').innerHTML = content;
    }
    function dropdownMenu(dropdownId) 
    {
        const x = document.getElementById(dropdownId);
        if (x.className.indexOf("w3-show") == -1) {
            x.className += " w3-show";
            x.previousElementSibling.className += " w3-green";
        }
        else {
            x.className = x.className.replace(" w3-show", "");
            x.previousElementSibling.className = x.previousElementSibling.className.replace(" w3-green", "");
        }
    }
    </script>
"@
    return $script
}