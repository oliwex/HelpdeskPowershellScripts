$Service = Get-CimInstance -ClassName Win32_Service -Filter "Name='NameNotExist'"

if ([string]::IsNullOrEmpty($Service.Description))
{
"asdasdas"
}