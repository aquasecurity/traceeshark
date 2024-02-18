rmdir /S /Q dist\workdir
mkdir dist\workdir

copy /Y dist\install.ps1 dist\workdir\install.ps1
copy /Y build\run\RelWithDebInfo\tracee-event dist\workdir\tracee-event.dll
copy /Y build\run\RelWithDebInfo\tracee-network-capture dist\workdir\tracee-network-capture.dll
copy /Y build\run\RelWithDebInfo\tracee-json dist\workdir\tracee-json.dll
xcopy /Y /E /I profiles dist\workdir\profiles

for /f "tokens=2" %%a in ('build\run\RelWithDebInfo\wireshark.exe --version ^| find "Wireshark "') do (
    for /f "tokens=1,2,3 delims=." %%A in ("%%a") do (
        set "WS_VERSION=%%A.%%B.%%C"
    )
)
echo %WS_VERSION% > dist\workdir\ws_version.txt

for /f "tokens=*" %%a in ('"git describe --tags --abbrev=0"') do set TRACEESHARK_VERSION=%%a

powershell Compress-Archive -Update -Path dist\workdir\* -DestinationPath dist\traceeshark-%TRACEESHARK_VERSION%-wireshark-%WS_VERSION%-windows-x86_64.zip