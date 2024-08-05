@echo off

if not exist "build" (
    echo Build directory doesn't exist, run "scripts\cmake.bat" first
    exit /b 1
)

robocopy .\ wireshark CMakeListsCustom.txt /COPY:DAT
robocopy plugins\epan wireshark\plugins\epan common.h /COPY:DAT
robocopy plugins\epan wireshark\plugins\epan wsjson_extensions.c /COPY:DAT
robocopy "plugins\epan\tracee-event" "wireshark\plugins\epan\tracee-event" /MIR /COPY:DAT
robocopy "plugins\epan\tracee-network-capture" "wireshark\plugins\epan\tracee-network-capture" /MIR /COPY:DAT
robocopy "plugins\wiretap\tracee-json" "wireshark\plugins\wiretap\tracee-json" /MIR /COPY:DAT

pushd build
msbuild /m /p:Configuration=RelWithDebInfo Wireshark.sln
popd