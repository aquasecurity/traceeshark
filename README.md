# Traceeshark

![](images/traceeshark_256x256.png)

1. [Getting started](#getting-started)

2. [Basic usage](#basic-usage)

3. [Build from source](#build-from-source)

## Getting started

The simplest way to install Traceeshark is using the autoinstall script.

First, make sure you have Python 3 installed, and your Wireshark installation is updated to the latest version.

Then, simply run the following command:

**Windows (powershell)**

```powershell
$outFile = [System.IO.Path]::GetTempFileName() ; Invoke-WebRequest -Uri "https://raw.githubusercontent.com/aquasecurity/traceeshark/main/autoinstall.py" -OutFile $outFile ; python.exe $outFile ; rm $outFile
```

**Linux/Mac**

```bash
outfile=$(mktemp) && curl -s "https://raw.githubusercontent.com/aquasecurity/traceeshark/main/autoinstall.py" > $outfile && python3 $outfile && rm $outfile
```

:information_source: Note that Traceeshark is compiled for a specific Wireshark verison. If you are using a Linux distribution with an outdated Wireshark package, the prebuilt releases of Traceeshark may not work. Ubuntu 22.04 and 24.04 have a dedicated release for their Wireshark package version.

### Setup for live capture

To use live capture, a few python libraries must be installed:

```
pip3 install paramiko msgpack python-pcapng
```

Additionally, the user must be able to run docker containers.

:information_source: This requirement is also applicable to remote servers you want to capture on, make sure the user you log in with can run docker.

On Linux, add your user to the docker group:

```bash
sudo usermod -aG docker <user>
```

On Windows and Mac, make sure docker desktop is installed and your user can run containers.

### Manual installation

Traceeshark can be installed using a release containing the plugins and other required files.

Installations are per Wireshark version and may not work with other versions. Download the appropriate release, unzip it, and run the installation script (`install.ps1` on Windows and `install.sh` on Linux/Mac)

:warning: The installation scripts must be run from within their directory

Now the plugins should be available to your Wireshark installation.

## Basic usage

When using Traceeshark for the first time, the Tracee configuration profile should be applied. The profile defines the custom column view, the event colors and some quick-filter buttons. Go to `Edit -> Configuration Profiles...` and select the "Tracee" profile.

### Live capture

Tracee live capture is implemented as an external capture program ("extcap" in Wireshark terminology). It is listed as ***Tracee capture*** together with regular network interfaces on the main screen. It has a settings icon next to it which allows managing Tracee's options before starting the capture.

#### Tracee options

To control what will be captured, the ***Tracee options*** tab can be used. Tracee options can be controlled by selecting a preset, by manually specifying command line options for Tracee, and by using the various selections available.

##### Presets

Presets allow defining a set of options for Tracee that will be used when performing a live capture. Use the ***Preset*** field to select which registered preset should be used for the capture, or select a custom preset file instead using the ***Preset file*** field. The `Default` preset which is installed with Traceeshark contains a set of useful events for a generic analysis use-case.

A preset file simply contains all of Tracee's command line arguments. It can either be selected directly, or placed in the preset directory for it to be listed in the preset selection.

The preset directory is at `~/.local/lib/wireshark/extcap/tracee-capture/presets` on Linux and Mac and at `%APPDATA%\Wireshark\extcap\tracee-capture\presets` on Windows.

:information_source: If you're using Wireshark 4.0.x or older on Linux/Mac, the preset directory will be at `~/.config/wireshark/extcap/tracee-capture/presets`.

##### Manually configured options

Tracee options can also be configured manually. The ***Tracee options*** tab allows to select which event sets to trace, the tracing scope (which processes and containers should be traced) and which artifacts to capture.

If a more advanced option is desired, the text box labeled ***Custom Tracee options*** allows specifying Tracee command line options directly.

:information_source: Any options configured will be used along with the preset, if selected.

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

:warning: On Windows, before cloning Traceeshark, make sure to run the following command: `git config --global core.autocrlf false`. Without this, git will insert carriage returns into the files and will break an important shell script!

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
