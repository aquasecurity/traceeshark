rmdir /S /Q wireshark\plugins\epan\tracee-event
rmdir /S /Q wireshark\plugins\epan\tracee-network-capture
rmdir /S /Q wireshark\plugins\wiretap\tracee-json
mkdir wireshark\plugins\epan\tracee-event
mkdir wireshark\plugins\epan\tracee-network-capture
mkdir wireshark\plugins\wiretap\tracee-json
copy /Y plugins\epan\tracee-event wireshark\plugins\epan\tracee-event
copy /Y plugins\epan\tracee-network-capture wireshark\plugins\epan\tracee-network-capture
copy /Y plugins\wiretap\tracee-json wireshark\plugins\wiretap\tracee-json
copy /Y CMakeListsCustom.txt wireshark
rmdir /S /Q build
mkdir build
pushd build
cmake -G "Visual Studio 17 2022" -A x64 -DENABLE_CCACHE=Yes ..\wireshark
popd