copy /Y plugins\epan\common.h wireshark\plugins\epan
copy /Y plugins\epan\wsjson_extensions.c wireshark\plugins\epan

copy /Y plugins\epan\tracee-event\internal_defs.c wireshark\plugins\epan\tracee-event
copy /Y plugins\epan\tracee-event\packet-tracee.c wireshark\plugins\epan\tracee-event
copy /Y plugins\epan\tracee-event\postdissectors.c wireshark\plugins\epan\tracee-event
copy /Y plugins\epan\tracee-event\tracee.h wireshark\plugins\epan\tracee-event
copy /Y plugins\epan\tracee-event\wanted_fields.c wireshark\plugins\epan\tracee-event

copy /Y plugins\epan\tracee-network-capture\packet-tracee-network-capture.c wireshark\plugins\epan\tracee-network-capture

copy /Y plugins\wiretap\tracee-json\tracee-json.c wireshark\plugins\wiretap\tracee-json

pushd build
msbuild /m /p:Configuration=RelWithDebInfo Wireshark.sln
popd