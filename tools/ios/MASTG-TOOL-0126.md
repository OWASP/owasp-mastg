---
title: libimobiledevice suite
platform: ios
host:
- macOS
- windows
- linux
source: https://libimobiledevice.org/
---

The libimobiledevice suite is cross-platform protocol library for interacting with iOS devices. The different libraries can be compiled into binaries for direct interaction with iOS devices from the command line.

!!! warning

    While many package repositories (apt, brew, cargo, ...) have versions of libimobiledevice tools, they are often outdated. We recommend compiling the different tools from source for the best results. Note that even if your package manager has the latest version based on `-v`, the source code will still be more up-to-date.

The following tools are part of the libimobiledevice suite:

| Tool | Purpose |
|------------------|---------------------|
| idevice_id | List attached devices or print device name of given device. |
| idevicebackup | Create or restore backup from the current or specified directory (<iOS 4). |
| idevicebackup2 | Create or restore backup from the current or specified directory (>= iOS 4). |
| idevicecrashreport | Move crash reports from device to a local DIRECTORY. |
| idevicedate | Display the current date or set it on a device. |
| idevicedebug | Interact with the debugserver service of a device. |
| idevicedebugserverproxy | Proxy debugserver connection from device to a local socket at PORT. |
| idevicediagnostics | Use diagnostics interface of a device running iOS 4 or later. |
| ideviceenterrecovery | Makes a device with the supplied UDID enter recovery mode immediately. |
| ideviceimagemounter | Mounts the specified disk image on the device. |
| ideviceinfo | Show information about a connected device. |
| ideviceinstaller | Manage apps on iOS devices. |
| idevicename | Display the device name or set it to NAME if specified. |
| idevicenotificationproxy | Post or observe notifications on a device. |
| idevicepair | Manage host pairings with devices and usbmuxd. |
| ideviceprovision | Manage provisioning profiles on a device. |
| idevicescreenshot | Gets a screenshot from a device. |
| idevicesetlocation | Sets the location on a device. |
| idevicesyslog | Relay syslog of a connected device. |
| inetcat | Opens a read/write interface via STDIN/STDOUT to a TCP port on a usbmux device. |
| iproxy | Proxy that binds local TCP ports to be forwarded to the specified ports on a usbmux device. |
| plistutil | Convert a plist FILE between binary, XML, JSON, and OpenStep format. |
