function Install-Program
{
    [CmdletBinding()]
    param (
        [Parameter(HelpMessage = "ComputerName to install program",ValueFromPipeline)]
        [Alias("Computer")]
        [string]$computerName
   )
   begin
   {}
   process
   {
        #skopiowanie plików instalacyjnych programu
        $localPath="C:\BC"
        $destination="C:\BC"
        Copy-Item -Path $localPath -Destination $destination -Recurse -Force

        #skopiowanie PsExec do folderu instalacji
        $localPath="C:\PSExec.exe"
        $destination="C:\PSExec.exe"
        Copy-Item -Path $localPath -Destination $destination -Recurse -Force

        PsExec.exe -accepteula -nobanner \\$computerName C:\BC\setup.exe -f2C:\BC\history.log -s -f1C:\BC\BC.iss

   }
   end
   {}


}

"Computer" | Install-Program