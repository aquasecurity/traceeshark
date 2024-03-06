# Traceeshark

## Installation

Traceeshark can be installed using an archive containing the plugins and other required files.

Archives are available in the downloads section. Installations are per Wireshark version and may not work with other versions. Download the appropriate archive and unzip it.

On Linux and Mac:

```bash
unzip -d <destination folder> <archive>
```

Run the install script. On Windows:

```batch
powershell -executionpolicy bypass -File .\install.ps1
```

On Linux:

```bash
cd <destination folder>
chmod +x install.sh
./install.sh
```

Now the plugins should be available using your installed Wireshark.

### Setup for live capture

To use live capture, the `paramiko` and `msgpack` python libraries must be installed:

```
pip3 install paramiko msgpack
```

Additionally, the user must be able to run docker containers.

:information_source: This requirement is also applicable to remote servers you want to capture on, make sure the user you log in with can run docker.

On Linux, add your user to the docker group:

```bash
sudo usermod -aG docker $USER
```

On Windows and Mac, make sure docker desktop is installed and your user can run containers.

## Basic usage

When using for the first time, the Tracee configuration profile needs to be applied, which defines the custom column view and the event colors. Go to `Edit -> Configuration Profiles...` and select the "Tracee" profile.

### Live capture

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

The general flow of building Traceeshark is as follows:

1. Clone Traceeshark

2. Clone Wireshark under the Traceeshark directory

3. Set up the build environment

4. Checkout the desired Wireshark version to build Traceeshark against

5. Configure Wireshark normally and install Wireshark's headers

6. Build Traceeshark

7. Optional: create a distribution archive

8. Repeat from step 4 to build against another version of Wireshark

### 1. Clone Traceeshark

```bash
git clone git@bitbucket.org:scalock/traceeshark.git
cd traceeshark
```

### 2. Clone Wireshark

Clone the Wireshark source into the Traceeshark directory (Makefile and build scripts depend on this location):

```bash
git clone https://github.com/wireshark/wireshark
```

### 3. Setting up the build environment

Follow Wireshark's instructions for setting up the build environment:

- [Linux & Mac](https://www.wireshark.org/docs/wsdg_html_chunked/ChapterSetup.html#ChSetupUNIXBuildEnvironmentSetup)

- [Windows](https://www.wireshark.org/docs/wsdg_html_chunked/ChSetupWindows.html) - follow sections 2.2.2 and 2.2.3. Ignore the instructions about setting up environmet variables, instead edit `scripts\setup_env.bat` with the appropriate paths to the Wireshark repository, the Qt installation and the Visual Studio installation. Run this script **in any new shell** you use to build Traceeshark/Wireshark.

### 4. Checkout the desired Wireshark version

Release versions of Wireshark have tags in the form `wireshark-x.y.z`. Checkout the desired tag, for example:

```bash
cd wireshark
git checkout wireshark-4.2.3
cd ..
```

:information_source: Note that source code compatibility of Traceeshark is not guaranteed, not all versions of Wireshark are supported. Incompatible versions will result in compilation errors.

### 5. Configure Wireshark and install headers

Configure Wireshark normally so the headers are generated and can be installed.

On Linux and Mac:

```bash
mkdir wireshark/build
cd wireshark/build
cmake ..
```

On Windows:

```batch
mkdir build
cd build
cmake -G "Visual Studio 17 2022" -A x64 ..\wireshark
```

:information_source: If `Visual Studio 17 2022` is not a valid toolchain on your system, you can list the available options using `cmake -G`

Next, install Wireshark's headers.

On Linux and Mac:

```bash
sudo make install-headers
```

On Windows (requires an elevated command prompt):

```batch
msbuild install-headers.vcxproj
```

Keep in mind that this stage needs to be repeated for every Wireshark version you want to build Traceeshark against.

### 6. Build Traceeshark

Building Traceeshark is managed using a Makefile on Linux and Mac and build scripts on Windows.

Before building for the first time, Wireshark needs to be configured again, this time for Traceeshark. This step needs to be performed any time there is a change to the Wireshark repository or to the file structure of Traceeshark.

On Linux and Mac:

```bash
make cmake
```

:warning: If your system does not have a Qt6 package available (e.g. Ubuntu 20.04 and older), run `make cmake USE_QT5=y` instead (this is necessary only if you plan running the Wireshark version that will be built, if you have a working Wireshark installation this is not necessary).

On Windows:

```batch
scripts\make_cmake.bat
```

Next, build Wireshark together with the Traceeshark plugins.

On Linux and Mac:

```bash
make
```

On Windows:

```batch
scripts\make.bat
```

The Linux and Mac Makefile has a few extra targets that are useful for development:

```bash
# Install plugins and other Traceeshark
# files into their destinations.
make install

# Run Wireshark from the build directory.
# Runs the install target automatically.
make run

# Same as run target, but with debug output enabled
make debug
```

### 7. Create a distribution archive

A distribution archive with an installation script can be created for anyone with the same OS and architecture. Note that a distribution targets the specific Wireshark version that was used while building. To build for a different version, go back to step 4.

On Linux and Mac:

```bash
make dist
```

On Windows:

```batch
scripts\make_dist.bat
```

The archive will be written to the `dist` directory.
