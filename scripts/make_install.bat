setlocal

FOR /F "tokens=*" %%i in ('type .env') do SET %%i

mkdir "%APPDATA%\Wireshark\profiles"
xcopy /Y /E /I profiles "%APPDATA%\Wireshark\profiles"

mkdir "%APPDATA%\Wireshark\extcap"
copy /Y extcap\tracee-capture.py "%APPDATA%\Wireshark\extcap\tracee-capture.py"
powershell -Command "(gc '%APPDATA%\Wireshark\extcap\tracee-capture.py') -replace 'VERSION_PLACEHOLDER', '%TRACEESHARK_VERSION%' | Out-File -encoding ASCII '%APPDATA%\Wireshark\extcap\tracee-capture.py'"
copy /Y extcap\tracee-capture.bat "%APPDATA%\Wireshark\extcap\tracee-capture.bat"
xcopy /Y /E /I extcap\tracee-capture "%APPDATA%\Wireshark\extcap\tracee-capture"

for /f "tokens=2" %%a in ('build\run\RelWithDebInfo\wireshark.exe --version ^| find "Wireshark "') do (
    for /f "tokens=1,2 delims=." %%A in ("%%a") do (
        set "WS_VERSION=%%A.%%B"
    )
)

mkdir "%APPDATA%\Wireshark\plugins\%WS_VERSION%\epan"
mkdir "%APPDATA%\Wireshark\plugins\%WS_VERSION%\wiretap"

copy /Y build\run\RelWithDebInfo\tracee-event.dll "%APPDATA%\Wireshark\plugins\%WS_VERSION%\epan\tracee-event.dll"
copy /Y build\run\RelWithDebInfo\tracee-network-capture.dll "%APPDATA%\Wireshark\plugins\%WS_VERSION%\epan\tracee-network-capture.dll"
copy /Y build\run\RelWithDebInfo\tracee-json.dll "%APPDATA%\Wireshark\plugins\%WS_VERSION%\wiretap\tracee-json.dll"

endlocal