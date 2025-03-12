---
title: Installing Apps
platform: android
---

## Basic APK Installation

Use `adb install` to install an APK on an emulator or connected device. The given path is the path of the APK on the host.

```bash
adb install ./myApp.apk
```

If multiple devices are connected, you can specify to install to a connected device (`-d`), emulator or TCP/IP device (`-e`) or specific serial number (`-s`).

```bash
# Install to connected physical device
adb -d install ./myApp.apk

# Install to emulator
adb -e install ./myApp.apk

# List all devices
adb devices
List of devices attached
37081JEHN05882  device
emulator-5554   device

# Connect to a specific device
adb -s 37081JEHN05882 install ./myApp.apk
```

When installing an app, it also possible to automatically grant all runtime permissions using `-g`:

```bash
adb install -g ./myApp.apk
```

## Installing a Repackaged App

In case there is already an application installed with the same package name, Android will compare the signatures. If the signatures match, the update will succeed. If the signature is different (for example, after repackaging an APK), the installation will fail.

```bash
adb install ./myRepackagedApp.apk
adb: failed to install myRepackagedApp.apk: Failure [INSTALL_FAILED_UPDATE_INCOMPATIBLE: Existing package org.owasp.mastestapp signatures do not match newer version; ignoring!]
```

To solve this issue, first remove the original application using `adb uninstall`:

```bash
# Uninstall based on package name
adb uninstall org.owasp.mastestapp

# Normal install via adb
adb install ./myRepackagedApp.apk
```

## Installing to a Specific Profile

To install an APK into a specific profile, the APK first has to be pushed to the device, as it is not possible to do this directly using `adb install`. Note that pushing to `/sdcard/` may result in permission issues, so use `/data/local/tmp` to be sure. After pushing the APK to the device, it can be installed using `pm install` with the `--user XX` option:

```bash
# Get an overview of available profiles
adb shell pm list users
Users:
    UserInfo{0:Owner:c13} running
    UserInfo{11:Sample Managed Profile:1030} running

# Push to /data/local/tmp/
adb push ./myApp.apk /data/local/tmp/

# Install with pm install and the --user option
adb shell pm install --user 11 /data/local/tmp/myRepackagedApp.apk
```

## Installing Split APKs

In case you need to install split APKs, you can use the `install-multiple` command. Make sure the different split APKs match your device configuration:

```bash
# Youtube is a split APK
adb shell pm path com.google.android.youtube
package:/data/app/~~ZLX3UNTF7R2oebU_viP7mw==/com.google.android.youtube-Rhm4GURIQ4twNvR6wxqc6w==/base.apk
package:/data/app/~~ZLX3UNTF7R2oebU_viP7mw==/com.google.android.youtube-Rhm4GURIQ4twNvR6wxqc6w==/split_config.arm64_v8a.apk
package:/data/app/~~ZLX3UNTF7R2oebU_viP7mw==/com.google.android.youtube-Rhm4GURIQ4twNvR6wxqc6w==/split_config.en.apk
package:/data/app/~~ZLX3UNTF7R2oebU_viP7mw==/com.google.android.youtube-Rhm4GURIQ4twNvR6wxqc6w==/split_config.xxhdpi.apk

# Obtain the different parts
adb pull /data/app/~~ZLX3UNTF7R2oebU_viP7mw==/com.google.android.youtube-Rhm4GURIQ4twNvR6wxqc6w==/base.apk
adb pull /data/app/~~ZLX3UNTF7R2oebU_viP7mw==/com.google.android.youtube-Rhm4GURIQ4twNvR6wxqc6w==/split_config.arm64_v8a.apk
adb pull /data/app/~~ZLX3UNTF7R2oebU_viP7mw==/com.google.android.youtube-Rhm4GURIQ4twNvR6wxqc6w==/split_config.en.apk
adb pull /data/app/~~ZLX3UNTF7R2oebU_viP7mw==/com.google.android.youtube-Rhm4GURIQ4twNvR6wxqc6w==/split_config.xxhdpi.apk

# Uninstall Youtube as a test
adb uninstall com.google.android.youtube

# Install the split APK files
adb install-multiple base.apk split_config.arm64_v8a.apk split_config.en.apk split_config.xxhdpi.apk
```
