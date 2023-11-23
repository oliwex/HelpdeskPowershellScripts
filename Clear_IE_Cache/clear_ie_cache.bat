@echo off
for /f "tokens=4-5 delims=. " %%i in ('ver') do set VERSION=%%i.%%j
for /D %%A in (C:\Users\*) do (
	if "%VERSION%" == "6.1" (
		if exist "%%A\AppData\Local\Microsoft\Windows\Temporary Internet Files\" (
			del /S /Q "%%A\AppData\Local\Microsoft\Windows\Temporary Internet Files\*"
		)
		if exist "%%A\AppData\Roaming\Microsoft\Windows\Cookies\" (
			del /S /Q "%%A\AppData\Roaming\Microsoft\Windows\Cookies\*"
		)
	) else (
		if exist "%%A\AppData\Local\Microsoft\Windows\INetCache\" (
			del /S /Q "%%A\AppData\Local\Microsoft\Windows\INetCache\*"
		)
		if exist "%%A\AppData\Local\Microsoft\Windows\INetCookies\" (
			del /S /Q "%%A\AppData\Local\Microsoft\Windows\INetCookies\*"
		)
	)
)