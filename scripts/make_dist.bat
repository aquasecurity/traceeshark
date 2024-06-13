setlocal

FOR /F "tokens=*" %%i in ('type .env') do SET %%i

rmdir /S /Q dist\workdir
mkdir dist\workdir

copy /Y dist\install.ps1 dist\workdir\install.ps1
copy /Y build\run\RelWithDebInfo\tracee-event dist\workdir\tracee-event.dll
copy /Y build\run\RelWithDebInfo\tracee-network-capture dist\workdir\tracee-network-capture.dll
copy /Y build\run\RelWithDebInfo\tracee-json dist\workdir\tracee-json.dll
xcopy /Y /E /I profiles dist\workdir\profiles
xcopy /Y /E /I extcap dist\workdir\extcap
powershell -Command "(gc dist\workdir\extcap\tracee-capture.py) -replace 'VERSION_PLACEHOLDER', '%TRACEESHARK_VERSION%' | Out-File -encoding ASCII dist\workdir\extcap\tracee-capture.py"

for /f "tokens=2" %%a in ('build\run\RelWithDebInfo\wireshark.exe --version ^| find "Wireshark "') do (
    for /f "tokens=1,2,3 delims=." %%A in ("%%a") do (
        set "WS_VERSION=%%A.%%B.%%C"
    )
)
echo %WS_VERSION% > dist\workdir\ws_version.txt

powershell Compress-Archive -Update -Path dist\workdir\* -DestinationPath dist\traceeshark-v%TRACEESHARK_VERSION%-windows-x86_64-wireshark-%WS_VERSION%.zip

endlocal