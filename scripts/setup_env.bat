rem Let CMake determine the library download directory name under
rem WIRESHARK_BASE_DIR or set it explicitly by using WIRESHARK_LIB_DIR.
rem Set *one* of these.
set WIRESHARK_BASE_DIR=C:\Projects\traceeshark
rem set WIRESHARK_LIB_DIR=c:\wireshark-x64-libs
rem Set the Qt installation directory
set WIRESHARK_QT6_PREFIX_PATH=C:\Tools\Qt\6.6.1\msvc2019_64
rem Append a custom string to the package version. Optional.
rem set WIRESHARK_VERSION_EXTRA=-YourExtraVersionInfo

"C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat"