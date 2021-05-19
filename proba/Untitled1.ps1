function Get-UserFromOU
{
Param(
        [Parameter(Mandatory=$true)]
        [alias("OU","OrganisationalUnit")]
        [String] $OUpath,
        [Switch] $extended
    )

    $data=Get-ADUser -Filter * -SearchBase $OUpath -SearchScope Onelevel -Properties AccountExpirationDate,AccountNotDelegated,AllowReversiblePasswordEncryption,CannotChangePassword,CanonicalName,Certificates,City,CN,Company,Country,Created,Department,Description,DisplayName,DistinguishedName,Division,EmailAddress,EmployeeID,EmployeeNumber,Enabled,Fax,GivenName,HomeDirectory,HomeDirRequired,HomeDrive,HomePage,HomePhone,Initials,LastLogonDate,LogonWorkstations,Manager,MemberOf,MobilePhone,Modified,Name,ObjectCategory,ObjectClass,ObjectGuid,Office,OfficePhone,Organization,OtherName,PasswordExpired,PasswordLastSet,PasswordNeverExpires,PasswordNotRequired,POBox,PostalCode,PrimaryGroup,ProfilePath,ProtectedFromAccidentalDeletion,SamAccountName,ScriptPath,ServicePrincipalName,SID,SIDHistory,SmartCardLogonRequired,State,StreetAddress,Surname,Title,TrustedForDelegation,TrustedToAuthForDelegation,UseDESKeyOnly,UserPrincipalName #,msDS-SupportedEncryptionTypes,User-Account-Control

    if ($extended)
    {
        $data
    }
    else
    {
        $data | Select DistinguishedName,GivenName,Name,ObjectClass,ObjectGuid,SamAccountName,SID,Surname,UserPrincipalName,CannotChangePassword,PasswordNeverExpires,AllowReversiblePasswordEncryption,Enabled,SmartCardLogonRequired,TrustedForDelegation,UseDESKeyOnly #,msDS-SupportedEncryptionTypes,User-Account-Control
    }
}

Get-UserFromOU -OUpath "OU=BDG,OU=UZYTKOWNICY,DC=domena,DC=local" -extended:$false
