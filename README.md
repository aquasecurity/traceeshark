# Traceeshark

## Installation

:warning: Currently on Windows, Traceeshark must be built from source.

Traceeshark can be installed using an archive containing the plugins and other required files.

Archives are available in the downloads section, grouped per tag. Installations are per Wireshark version and may not work with other versions. Download the appropriate archive and unzip it:

```bash
unzip -d <destination folder> <archive>
```

Mark the install script as executable:

```bash
cd <destination folder>
chmod +x install.sh
```

Run the install script:

:warning: NOTE: installation is per user and root may be required for using local live capture, so run this on any user you will be using Traceeshark with

```bash
./install.sh
```

Now the plugins should be available to your Wireshark installation.

## Basic usage

When using for the first time, the Tracee configuration profile needs to be applied, which defines the custom column view and the event colors. Go to `Edit -> Configuration Profiles...` and select the "Tracee" profile.

### Live capture

Currently live capture can only be done locally, which means only Linux is supported.

Tracee live capture is implemented as an external capture program ("extcap" in Wireshark terminology). It is listed as "Tracee: capture" together with regular network interfaces on the main screen. It has a settings icon next to it which allows managing Tracee's options before starting the capture.

#### Preset system

Currently, persistent management of runtime configuration for Tracee is available using a preset system, configurable via the "Preset control" tab in the configuration window. Use the "Preset" field to select which preset should be used for the capture. If the "No preset" option is specfied, the "Tracee options" tab will be used for manually specifying the options.

Instead of selecting a pre-registered preset, a custom preset file can be used instead. A preset file simply contains all of Tracee's command line arguments in one line.

A custom preset file can be registered to the preset list using the "Update preset from file" option. With this option a new preset can be registered based on the name of the selected file, or an existing preset can be updated.

Additionally, a registered preset can be deleted using the "Delete preset" option.

:information_source: After registering/updating/deleting a preset, the preset list needs to be updated using the "Reload presets" button. The preset lists in "Update preset from file" and "Delete preset" do not update from operations performed by a different option, they will only be updated after reopening the configuration window.

#### Manually configured options

Tracee options can be configured manually using the "Tracee options" tab. Currently the only way to specifty options is by entering Tracee's command line options directly (or leaving it blank for no options). In the future, options will be able to be selected interactively.

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

Install dependencies as specified in the [Wireshark developer's guide](https://www.wireshark.org/docs/wsdg_html_chunked/ChapterSetup.html#ChSetupUNIXBuildEnvironmentSetup).

For example, on Ubuntu:

```bash
sudo wireshark/tools/debian-setup.sh
```

Before building for the first time, run `make cmake`.

:warning: If your system does not have a Qt6 package available (e.g. Ubuntu 20.04 and older), run `make cmake USE_QT5=y` instead.

To build only, use `make`. To install configuration and extcap, run `make install`. To build and run, use `make run`.

### Plugin distribution

The `make dist` target places all built plugins and other files into a zip archive with an install script, under the `dist` directory. The archive can be distributed and installed by anyone with the same OS and architecture. Plugin compatibility is not guaranteed with Wireshark versions different than the one they were compiled with. If you want to compile for a different Wireshark version, checkout that version from the Wireshark repository before building (source code compatibility not guaranteed, may result in compilation errors).
