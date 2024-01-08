# Traceeshark

## Basic Usage

To apply the Tracee configuration profile, which defines the custom column view and the event colors, select `Edit -> Configuration Profiles...` and select the "Tracee" profile.

## Build from source

:warning: This method works only for Linux and Mac.

Clone with the Wireshark submodule:

```bash
git clone --recurse-submodules git@bitbucket.org:scalock/traceeshark.git
```

Before building for the first time, run `make cmake`.

To build only, use `make`. To build and run, use `make run`.

After building, the plugin libraries will be placed in the wireshark subdirectory at `wireshark/build/run/plugins/epan/tracee-epan.so.1` and `wireshark/build/run/plugins/wiretap/tracee-wtap.so.1`.

These can be used with any Wireshark installation by placing them under `~/.local/lib/wireshark/plugins`.

The `profiles/Tracee` folder which defines the custom view of columns and the coloring of events needs to be placed at `~/.config/wireshark/profiles/Tracee`. The `make run` command already places them there.


