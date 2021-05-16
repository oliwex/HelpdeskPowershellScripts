$(Get-ADOrganizationalUnit -Filter *).DistinguishedName

$OUpath = 'OU=WIOH,OU=DN,OU=UZYTKOWNICY,DC=domena,DC=local'
Get-ADUser -Filter * -SearchBase $OUpath -Properties AccountExpirationDate,AccountNotDelegated,AllowReversiblePasswordEncryption,CannotChangePassword,CanonicalName,Certificates,City,CN,Company,Country,Created,Department,Description,DisplayName,DistinguishedName,Division,EmailAddress,EmployeeID,EmployeeNumber,Enabled,Fax,GivenName,HomeDirectory,HomeDirRequired,HomeDrive,HomePage,HomePhone,Initials,LastLogonDate,LogonWorkstations,Manager,MemberOf,