@echo off
setlocal

FOR /F "tokens=*" %%i in ('type .env') do SET %%i

call make_clean.bat
robocopy .\ wireshark CMakeListsCustom.txt /COPY:DAT
robocopy plugins\epan wireshark\plugins\epan common.h /COPY:DAT
robocopy plugins\epan wireshark\plugins\epan wsjson_extensions.c /COPY:DAT
robocopy "plugins\epan\tracee-event" "wireshark\plugins\epan\tracee-event" /MIR /COPY:DAT
robocopy "plugins\epan\tracee-network-capture" "wireshark\plugins\epan\tracee-network-capture" /MIR /COPY:DAT
robocopy "plugins\wiretap\tracee-json" "wireshark\plugins\wiretap\tracee-json" /MIR /COPY:DAT
mkdir build
pushd build

rem Wireshark changed DISABLE_WERROR to ENABLE_WERROR at some point. Use both for compatibility (even though it causes a cmake warning to be thrown)
if "%WERROR%"=="y" (
    cmake -G "Visual Studio 17 2022" -A x64 -DENABLE_MINIZIPNG=Off -DTRACEESHARK_VERSION=%TRACEESHARK_VERSION% -DENABLE_CCACHE=Yes -DENABLE_WERROR=ON -DDISABLE_WERROR=OFF ..\wireshark
) else (
    cmake -G "Visual Studio 17 2022" -A x64 -DENABLE_MINIZIPNG=Off -DTRACEESHARK_VERSION=%TRACEESHARK_VERSION% -DENABLE_CCACHE=Yes -DENABLE_WERROR=OFF -DDISABLE_WERROR=OFF ..\wireshark
)

popd

endlocal