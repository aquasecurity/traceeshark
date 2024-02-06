# Traceeshark

## Installation

:warning: Currently on Windows, Traceeshark must be built from source.

Traceeshark can be installed using an archive containing prebuilt Wireshark.

Archives are available in the downloads section. Download the appropriate archive and unzip it:

```bash
unzip -d <destination folder> <archive>
```

Then run the install script:

```bash
cd <destination folder>
chmod +x install.sh

# NOTE: installation is per user and root may be
# required for using local live capture, so run
# this on any user you will be using Traceeshark with
./install.sh
```

You may need to install some libraries to run Wireshark.

On Ubuntu:

```bash
sudo apt install qt6-multimedia-dev libqt6core5compat6 libc-ares-dev
```

Finally, run Wireshark:

```bash
run/wireshark
```

## Basic Usage

To apply the Tracee configuration profile, which defines the custom column view and the event colors, select `Edit -> Configuration Profiles...` and select the "Tracee" profile.

## Build from source

:warning: This method works only for Linux and Mac.

Clone the repository:

```bash
git clone git@bitbucket.org:scalock/traceeshark.git
cd traceeshark
```

Clone the Wireshark source into the Traceeshark directory (Makefile and build scripts depend on this location):

```bash
git clone https://github.com/wireshark/wireshark
```

Before building for the first time, run `make cmake`.

To build only, use `make`. To build and run, use `make run`.

After building, the plugin libraries will be placed in the wireshark subdirectory at `wireshark/build/run/plugins/epan/tracee-epan.so.1` and `wireshark/build/run/plugins/wiretap/tracee-wtap.so.1`.

These can be used with any Wireshark installation by placing them under `~/.local/lib/wireshark/plugins`.

The `profiles/Tracee` folder which defines the custom view of columns and the coloring of events needs to be placed at `~/.config/wireshark/profiles/Tracee`. The `make run` command already places them there.
