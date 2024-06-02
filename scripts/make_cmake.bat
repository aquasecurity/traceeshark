setlocal

FOR /F "tokens=*" %%i in ('type .env') do SET %%i

rmdir /S /Q wireshark\plugins\epan\tracee-event
rmdir /S /Q wireshark\plugins\epan\tracee-network-capture
rmdir /S /Q wireshark\plugins\wiretap\tracee-json
del /Q wireshark\plugins\epan\common.h
del /Q wireshark\plugins\epan\wsjson_extensions.c
xcopy /Y /E plugins wireshark\plugins\
copy /Y CMakeListsCustom.txt wireshark
rmdir /S /Q build
mkdir build
pushd build
cmake -G "Visual Studio 17 2022" -A x64 -DTRACEESHARK_VERSION=%TRACEESHARK_VERSION% ..\wireshark
popd

endlocal