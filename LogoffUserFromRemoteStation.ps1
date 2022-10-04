
#Get session id of local user logged in by: quser /server:ComputerName
Invoke-Command -ComputerName ComputerName -ScriptBlock { logoff 5 } # logoff user by session id from quser /server:ComputerName