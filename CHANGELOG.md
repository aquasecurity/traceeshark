# Changelog

## v0.3.8

**Changed:**

- Releases are now built for Wireshark 4.4.5 instead of 4.4.3

**Fixed:**

- Dissection fixes

## v0.3.7

**Added:**

* Stats: added process tree with opened files

**Changed:**

* Stats: renamed process tree with files to process tree with written files

* Releases are now built for Wireshark 4.4.3 instead of 4.4.1

## v0.3.6

**Added:**

- Enrichments: `prev_comm` field was added to `sched_process_exec` description

- Stats: added preferences for filtering unix sockets in process tree with network

**Changed:**

- Live capture: default docker image was changed to v0.22.2

- Releases are now built for Wireshark 4.4.1 instead of 4.4.0

**Fixed:**

- Installation script fixes

- Remote capture: remove reliance on `$PPID` variable that doesn't exist in some shells

## v0.3.5

**Added:**

- Releases for Linux ARM64

- Statistics:
  
  - File Types 
  
  - Add per-container view to all existing statistics

- Enhanced file type detection for `magic_write`

- Support for more special argument datatypes

**Changed:**

- Live capture: increase modularity

**Fixed:**

- Live capture bugfixes

## v0.3.4

**Added:**

- Releases for Wireshark 4.4.0

- Live capture: packet events (`net_packet_raw`) can be selected in event sets

**Changed:**

- Live capture: default docker image was changed to v0.22.0

**Fixed:**

- Build and install script fixes

## v0.3.3

**Added:**

- Live capture - add packet event to event set selection

**Fixed:**

- Live capture fixes

## v0.3.2

**Added:**

- Documentation

- Tracee packet capture context dissection (new Tracee feature)

- Script that merges Tracee pcaps with events

- IP addresses and ports in network events are now displayed in the appropriate columns

- Support for various special event argument data types

**Changed:**

- Releases are now built for Wireshark 4.2.6
- Command line argument in process execution events is now displayed as a generated field
- Live capture
  - Default docker image was changed to a recent development snapshot
  - New packet event was added to the ***Default*** preset

**Fixed:**

- Makefile and build script improvements
- Dissector and stats fixes
- Live capture fix for older Tracee versions

**Removed:**

- Live capture packet injector (no longer needed thanks to new packet event)

## v0.3.1

**Added:**

- Pull request build workflow

- Build worflow step that tests that the plugins are loaded successfully

- Statistics
  
  - Process tree with written files
  
  - Process tree with network operations
  
  - Process tree with signatures
  
  - Add process executable and command line to process nodes

**Changed:**

- Process tree
  
  - Only paths relevant to the selected filter are displayed
  
  - Process fork events are used to determine the parent

**Fixed:**

- Compilation and loading errors on older and newer Wireshark versions

- Stats tree bugfixes

- Makefile fixes on Macos

## v0.3.0 (has issues)

**Added**:

- Column format preferences
  
  - Decide whether to display host PID, namespace PID or both
  
  - Decide whether to display container ID or name
  
  - Decide whether to append container image

- Source and destination IP columns in Tracee profile

- Signature arguments in info column

- Event enrichments
  
  - `security_socket_connect`
  
  - `security_sockert_bind`
  
  - `dynamic_code_loading`
  
  - `fileless_execution`
  
  - `stdio_over_socket`
  
  - `magic_write` - add decoded magic and some recognized file types
  
  - `security_file_open`

- Live capture
  
  - Default capture preset
  - Logs and errors can be accessed from toolbar

- Statistics
  
  - Event counts
  - Process tree

- Dissection of the new `net_packet_raw` event, which hands off the packet dissection to Wireshark

- Traceeshark logo

**Changed**:

- Reorganized dissection tree structure

- Revised "Important" filter button

- Revised "Network" filter button

- Event argument filters are now namespaced according to event name

- Live capture
  
  - Tracee options and presets are not mututally exclusive anymore
  
  - Simplified preset system
  
  - Pin default Tracee docker image to current stable release

- README.md updates

**Fixed**:

- Live capture bugfixes

- Tracee event dissector bugfixes

- Makefile, build script and install script fixes

## v0.2.3

**Added**:

- Autoinstall script

- Release for Wireshark version 4.2.2 on Linux (Ubuntu 24.04 Wireshark package version)

**Fixed**:

- Macos build and installation fixes

- Windows build fixes

- Live capture bugfixes

## v0.2.2

**Added**:

- Live capture
  
  - Remove container from previous run
  
  - Add configuration for capturing artifacts
  
  - Added toolbar for controlling the capture
  
  - Remote capture - copy artifacts from remote machine on demand and on capture stop
  
  - Inject captured packets into event stream on demand, periodically, and on capture stop

- Added GitHub workflow for automatic builds across all platforms

**Fixed**:

- Live capture bugfixes

## v0.2.1

**Changed**:

- Exclude SSH tunnel PID in remote capture
- Traceeshark version is specified once for building in the `.env` file

**Fixed**:

- extcap bugfixes

- Install scripts now determine the correct installation folders based on the Wireshark version

## v0.2.0

**Added**:

- Remote live capturing

- Local live capturing on Windows and Mac using docker desktop's VM

**Fixed**:

- Makefile and install script bug on Mac

## v0.1.2

**Added**:

- Ability to specify logfile for live capture

- Ability to configure desired event sets and scope options for live capture

- Special data type dissection:
  
  - trace.PacketMetadata
  
  - trace.ProtoHTTP
  
  - map[string]trace.HookedSymbolData
  
  - []trace.HookedSymbolData
  
  - []trace.DnsResponseData

**Changed**:

- Refactored handling of complex argument types

**Fixed**:

- More robust identification of signatures instead of relying on "sig_" prefix

- Prevent native Wireshark color rules from overriding Tracee color rules

- Prevent live captured events from being identified as packets recorded by Tracee

## v0.1.1

**Added**:

- Build and distribution for Windows

- Build instructions in README.md

**Changed**:

- Tracee network capture dissector is now a postdissector instead of overriding the NULL/Loopback dissector

**Fixed**:

- Distribution and Wireshark compatibility fixes

## v0.1.0

Initial release.

**Features**:

- Ability to load Tracee JSON output files into Wireshark

- Dissection of Tracee JSON events:
  
  - General event fields
  
  - Basic arguments (fields registered dynamically according to argument type)
  
  - Special arguments (complex data types):
    
    - String arrays
    
    - Process lineage
    
    - struct sockaddr*
    
    - slim_cred_t
    
    - trace.PktMeta
    
    - []trace.DnsQueryData
    
    - trace.ProtoHTTPRequest
  
  - Dissection of arguments in "triggered by" (for signatures)
  
  - Network related fields added as fields of the appropriate Wireshark native dissector for that protocol, so network events can now be filtered using native Wireshark filters.
  
  - Arguments listed in info column
  
  - Selected events override info column with a custom, concise messsage

- Dissection of packet captures generated by Tracee. This dissector adds Tracee context based on the interface description, a feature which is not yet part of Tracee.

- Tracee profile for Wireshark
  
  - Custom columns tailored for Tracee events
  
  - Custom coloring based on event types
  
  - Quick filter butttons for common event categories
  
  - Bookmarked filters for common filtering operations

- Live capture using an extcap that runs a Tracee docker container and streams its events to Wireshark
  
  - Local live capture on Linux
  
  - Ability to specift command line options for Tracee
  
  - Preset system for saved Tracee command lines
