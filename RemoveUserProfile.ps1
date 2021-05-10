#Remove user from filesystem-Registry settings and files


$user="testUser"
Function Remove-UserProfile($userName)
{
    $userProfile=Get-CimInstance -Class Win32_UserProfile | Where-Object { $_.LocalPath.split('\')[-1] -eq $userName } | Remove-CimInstance
    Remove-Item -Recurse -Force ($userProfile).LocalPath
}

Remove-UserProfile -userName $user


