# The following code will create an IIS site and it associated Application Pool. 
# Please note that you will be required to run PS with elevated permissions. 
# Visit http://ifrahimblog.wordpress.com/2014/02/26/run-powershell-elevated-permissions-import-iis-module/ 

# set-executionpolicy unrestricted
Import-Module ServerManager
Add-WindowsFeature Web-Scripting-Tools
Import-Module WebAdministration 

$SiteFolderPath = "C:\WebSite"              # Website Folder
$SiteAppPool = "MinioPool"                  # Application Pool Name
$SiteName = "MinioSite"                        # IIS Site Name
$SiteHostName = "www.MinioSite.com"            # Host Header

New-Item $SiteFolderPath -type Directory
Set-Content $SiteFolderPath\Default.htm "<h1>Hello IIS</h1>"
New-Item IIS:\AppPools\$SiteAppPool
New-Item IIS:\Sites\$SiteName -physicalPath $SiteFolderPath -bindings @{protocol="http";bindingInformation=":80:"+$SiteHostName}
Set-ItemProperty IIS:\Sites\$SiteName -name applicationPool -value $SiteAppPool

# Complete