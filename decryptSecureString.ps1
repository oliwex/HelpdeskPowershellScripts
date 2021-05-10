$lama=("P@ssword1" | ConvertTo-SecureString -AsPlainText -Force)
[System.Runtime.InteropServices.marshal]::PtrToStringAuto([System.Runtime.InteropServices.marshal]::SecureStringToBSTR($lama))