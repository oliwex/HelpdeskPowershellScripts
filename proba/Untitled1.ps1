function Get-UserFromOU
{
Param(
        [Parameter(Mandatory=$true)]
        [alias("OU","OrganisationalUnit")]
        [String] $OUpath,
        [Switch] $extended
    )

    $data=Get-ADUser -Filter * -SearchBase $OUpath -SearchScope Onelevel -Properties *

    if ($extended)
    {
        $data
    }
    else
    {
        $data | Select DistinguishedName,GivenName,Name,ObjectClass,ObjectGuid,SamAccountName,SID,Surname,UserPrincipalName,CannotChangePassword,PasswordNeverExpires,AllowReversiblePasswordEncryption,Enabled,SmartCardLogonRequired,TrustedForDelegation,UseDESKeyOnly,msDS-SupportedEncryptionTypes <# This Account support Kerberos 128/256 Auth mają 8 lub 16 wartosc, gdy sa oba to maja 24 #>
    }
}

Get-UserFromOU -OUpath "OU=BDG,OU=UZYTKOWNICY,DC=domena,DC=local" -extended:$false
