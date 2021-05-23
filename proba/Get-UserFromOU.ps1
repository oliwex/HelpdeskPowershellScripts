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
        $data | Select DistinguishedName,GivenName,Name,ObjectClass,ObjectGuid,SamAccountName,SID,Surname,UserPrincipalName,CannotChangePassword,PasswordNeverExpires,AllowReversiblePasswordEncryption,Enabled,SmartCardLogonRequired,TrustedForDelegation,UseDESKeyOnly,msDS-SupportedEncryptionTypes,userAccountControl
    }
}

Get-UserFromOU -OUpath "OU=BDG,OU=UZYTKOWNICY,DC=domena,DC=local" -extended:$false
