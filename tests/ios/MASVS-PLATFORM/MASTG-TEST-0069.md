---
masvs_v1_id:
- MSTG-PLATFORM-1
masvs_v2_id:
- MASVS-PLATFORM-1
platform: ios
title: Testing App Permissions
masvs_v1_levels:
- L1
- L2
---

## Overview

## Static Analysis

Since iOS 10, these are the main areas which you need to inspect for permissions:

- Purpose Strings in the Info.plist File
- Code Signing Entitlements File
- Embedded Provisioning Profile File
- Entitlements Embedded in the Compiled App Binary
- Source Code Inspection

### Review application source code

If having the original source code, you can verify the permissions included in the `Info.plist` file:

- Open the project with Xcode.
- Find and open the `Info.plist` file in the default editor and search for the keys starting with `"Privacy -"`.

You may switch the view to display the raw values by right-clicking and selecting "Show Raw Keys/Values" (this way for example `"Privacy - Location When In Use Usage Description"` will turn into `NSLocationWhenInUseUsageDescription`).

<img src="Images/Chapters/0x06h/purpose_strings_xcode.png" width="100%" />

### Review Info.plist

If only having the IPA:

- Unzip the IPA.
- The `Info.plist` is located in `Payload/<appname>.app/Info.plist`.
- Convert it if needed (e.g. `plutil -convert xml1 Info.plist`) as explained in the chapter "iOS Basic Security Testing", section "The Info.plist File".
- Inspect all _purpose strings Info.plist keys_, usually ending with `UsageDescription`:

    ```xml
    <plist version="1.0">
    <dict>
        <key>NSLocationWhenInUseUsageDescription</key>
        <string>Your location is used to provide turn-by-turn directions to your destination.</string>
    ```

For each purpose string in the `Info.plist` file, check if the permission makes sense.

For example, imagine the following lines were extracted from a `Info.plist` file used by a Solitaire game:

```xml
<key>NSHealthClinicalHealthRecordsShareUsageDescription</key>
<string>Share your health data with us!</string>
<key>NSCameraUsageDescription</key>
<string>We want to access your camera</string>
```

It should be suspicious that a regular solitaire game requests this kind of resource access as it probably does not have any need for [accessing the camera](https://developer.apple.com/library/archive/documentation/General/Reference/InfoPlistKeyReference/Articles/CocoaKeys.html#//apple_ref/doc/uid/TP40009251-SW24 "NSCameraUsageDescription") nor a [user's health-records](https://developer.apple.com/library/archive/documentation/General/Reference/InfoPlistKeyReference/Articles/CocoaKeys.html#//apple_ref/doc/uid/TP40009251-SW76 "NSHealthClinicalHealthRecordsShareUsageDescription").

Apart from simply checking if the permissions make sense, further analysis steps might be derived from analyzing purpose strings e.g. if they are related to storage sensitive data. For example, `NSPhotoLibraryUsageDescription` can be considered as a storage permission giving access to files that are outside of the app's sandbox and might also be accessible by other apps. In this case, it should be tested that no sensitive data is being stored there (photos in this case). For other purpose strings like `NSLocationAlwaysUsageDescription`, it must be also considered if the app is storing this data securely. Refer to the "Testing Data Storage" chapter for more information and best practices on securely storing sensitive data.

### Review Embedded Provisioning Profile File

When you do not have the original source code, you should analyze the IPA and search inside for the _embedded provisioning profile_ that is usually located in the root app bundle folder (`Payload/<appname>.app/`) under the name `embedded.mobileprovision`.

This file is not a `.plist`, it is encoded using [Cryptographic Message Syntax](https://en.wikipedia.org/wiki/Cryptographic_Message_Syntax "Cryptographic Message Syntax"). On macOS you can [inspect an embedded provisioning profile's entitlements](https://developer.apple.com/library/archive/technotes/tn2415/_index.html#//apple_ref/doc/uid/DTS40016427-CH1-PROFILESENTITLEMENTS "Inspecting a profile\'s entitlements") using the following command:

```bash
security cms -D -i embedded.mobileprovision
```

and then search for the Entitlements key region (`<key>Entitlements</key>`).

### Review Entitlements Embedded in the Compiled App Binary

If you only have the app's IPA or simply the installed app on a jailbroken device, you normally won't be able to find `.entitlements` files. This could be also the case for the `embedded.mobileprovision` file. Still, you should be able to extract the entitlements property lists from the app binary yourself (which you've previously obtained as explained in the "iOS Basic Security Testing" chapter, section ["Acquiring the App Binary"](../../../Document/0x06b-iOS-Security-Testing.md#acquiring-the-app-binary)).

The following steps should work even when targeting an encrypted binary. If for some reason they don't, you'll have to decrypt and extract the app with e.g. Clutch (if compatible with your iOS version), frida-ios-dump or similar.

#### Extracting the Entitlements Plist from the App Binary

If you have the app binary on your computer, one approach is to use binwalk to extract (`-e`) all XML files (`-y=xml`):

```bash
$ binwalk -e -y=xml ./Telegram\ X

DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------
1430180       0x15D2A4        XML document, version: "1.0"
1458814       0x16427E        XML document, version: "1.0"
```

Or you can use radare2 (`-qc` to _quietly_ run one command and exit) to search all strings on the app binary (`izz`) containing "PropertyList" (`~PropertyList`):

```bash
$ r2 -qc 'izz~PropertyList' ./Telegram\ X

0x0015d2a4 ascii <?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n<!DOCTYPE plist PUBLIC
"-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">\n<plist version="1.0">
...<key>com.apple.security.application-groups</key>\n\t\t<array>
\n\t\t\t<string>group.ph.telegra.Telegraph</string>...

0x0016427d ascii H<?xml version="1.0" encoding="UTF-8"?>\n<!DOCTYPE plist PUBLIC
"-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">\n<plist version="1.0">\n
<dict>\n\t<key>cdhashes</key>...
```

In both cases (binwalk or radare2) we were able to extract the same two `plist` files. If we inspect the first one (0x0015d2a4) we see that we were able to completely recover the [original entitlements file from Telegram](https://github.com/peter-iakovlev/Telegram-iOS/blob/77ee5c4dabdd6eb5f1e2ff76219edf7e18b45c00/Telegram-iOS/Telegram-iOS-AppStoreLLC.entitlements "Telegram-iOS-AppStoreLLC.entitlements original file").

> Note: the `strings` command will not help here as it will not be able to find this information. Better use grep with the `-a` flag directly on the binary or use radare2 (`izz`)/rabin2 (`-zz`).

If you access the app binary on the jailbroken device (e.g via SSH), you can use grep with the `-a, --text` flag (treats all files as ASCII text):

```bash
$ grep -a -A 5 'PropertyList' /var/containers/Bundle/Application/
    15E6A58F-1CA7-44A4-A9E0-6CA85B65FA35/Telegram X.app/Telegram\ X

<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
    <dict>
        <key>com.apple.security.application-groups</key>
        <array>
        ...
```

Play with the `-A num, --after-context=num` flag to display more or less lines. You may use tools like the ones we presented above as well, if you have them also installed on your jailbroken iOS device.

> This method should work even if the app binary is still encrypted (it was tested against several App Store apps).

#### Source Code Inspection

After having checked the `<appname>.entitlements` file and the `Info.plist` file, it is time to verify how the requested permissions and assigned capabilities are put to use. For this, a source code review should be enough. However, if you don't have the original source code, verifying the use of permissions might be specially challenging as you might need to reverse engineer the app, refer to the "Dynamic Analysis" for more details on how to proceed.

When doing a source code review, pay attention to:

- whether the _purpose strings_ in the `Info.plist` file match the programmatic implementations.
- whether the registered capabilities are used in such a way that no confidential information is leaking.

Users can grant or revoke authorization at any time via "Settings", therefore apps normally check the authorization status of a feature before accessing it. This can be done by using dedicated APIs available for many system frameworks that provide access to protected resources.

You can use the [Apple Developer Documentation](https://developer.apple.com/documentation/uikit/core_app/protecting_the_user_s_privacy/accessing_protected_resources?language=objc#3037319 "Check for Authorization") as a starting point. For example:

- Bluetooth: the [`state`](https://developer.apple.com/documentation/corebluetooth/cbmanager/1648600-state?language=objc "CBManager state") property of the [`CBCentralManager`](https://developer.apple.com/documentation/corebluetooth/cbcentralmanager?language=objc "CBCentralManager") class is used to check system-authorization status for using Bluetooth peripherals.
- Location: search for methods of `CLLocationManager`, e.g. [`locationServicesEnabled`](https://developer.apple.com/documentation/corelocation/cllocationmanager/1423648-locationservicesenabled?language=objc "CLLocationManager locationServicesEnabled").

    ```default
    func checkForLocationServices() {
        if CLLocationManager.locationServicesEnabled() {
            // Location services are available, so query the user’s location.
        } else {
            // Update your app’s UI to show that the location is unavailable.
        }
    }
    ```

    See Table1 in ["Determining the Availability of Location Services"](https://developer.apple.com/documentation/corelocation/adding_location_services_to_your_app "Getting the availability of Core Location services") (Apple Developer Documentation) for a complete list.

Go through the application searching for usages of these APIs and check what happens to sensitive data that might be obtained from them. For example, it might be stored or transmitted over the network, if this is the case, proper data protection and transport security should be additionally verified.

### Dynamic Analysis

With help of the static analysis you should already have a list of the included permissions and app capabilities in use. However, as mentioned in "Source Code Inspection", spotting the sensitive data and APIs related to those permissions and app capabilities might be a challenging task when you don't have the original source code. Dynamic analysis can help here getting inputs to iterate onto the static analysis.

Following an approach like the one presented below should help you spotting the mentioned sensitive data and APIs:

1. Consider the list of permissions / capabilities identified in the static analysis (e.g. `NSLocationWhenInUseUsageDescription`).
2. Map them to the dedicated APIs available for the corresponding system frameworks (e.g. `Core Location`). You may use the [Apple Developer Documentation](https://developer.apple.com/documentation/uikit/core_app/protecting_the_user_s_privacy/accessing_protected_resources?language=objc#3037319 "Check for Authorization") for this.
3. Trace classes or specific methods of those APIs (e.g. `CLLocationManager`), for example, using [`frida-trace`](https://www.frida.re/docs/frida-trace/ "frida-trace").
4. Identify which methods are being really used by the app while accessing the related feature (e.g. "Share your location").
5. Get a backtrace for those methods and try to build a call graph.

Once all methods were identified, you might use this knowledge to reverse engineer the app and try to find out how the data is being handled. While doing that you might spot new methods involved in the process which you can again feed to step 3. above and keep iterating between static and dynamic analysis.

In the following example we use Telegram to open the share dialog from a chat and frida-trace to identify which methods are being called.

First we launch Telegram and start a trace for all methods matching the string "authorizationStatus" (this is a general approach because more classes apart from `CLLocationManager` implement this method):

```bash
frida-trace -U "Telegram" -m "*[* *authorizationStatus*]"
```

> `-U` connects to the USB device. `-m` includes an Objective-C method to the traces. You can use a [glob pattern](https://en.wikipedia.org/wiki/Glob_%28programming%29 "Glob (programming)") (e.g. with the "*" wildcard, `-m "*[* *authorizationStatus*]"` means "include any Objective-C method of any class containing 'authorizationStatus'"). Type `frida-trace -h` for more information.

Now we open the share dialog:

<img src="Images/Chapters/0x06h/telegram_share_something.png" width="400px" />

The following methods are displayed:

```bash
  1942 ms  +[PHPhotoLibrary authorizationStatus]
  1959 ms  +[TGMediaAssetsLibrary authorizationStatusSignal]
  1959 ms     | +[TGMediaAssetsModernLibrary authorizationStatusSignal]
```

If we click on **Location**, another method will be traced:

```bash
 11186 ms  +[CLLocationManager authorizationStatus]
 11186 ms     | +[CLLocationManager _authorizationStatus]
 11186 ms     |    | +[CLLocationManager _authorizationStatusForBundleIdentifier:0x0 bundle:0x0]
```

Use the auto-generated stubs of frida-trace to get more information like the return values and a backtrace. Do the following modifications to the JavaScript file below (the path is relative to the current directory):

```javascript

// __handlers__/__CLLocationManager_authorizationStatus_.js

  onEnter: function (log, args, state) {
    log("+[CLLocationManager authorizationStatus]");
    log("Called from:\n" +
        Thread.backtrace(this.context, Backtracer.ACCURATE)
        .map(DebugSymbol.fromAddress).join("\n\t") + "\n");
  },
  onLeave: function (log, retval, state) {
    console.log('RET :' + retval.toString());
  }
```

Clicking again on "Location" reveals more information:

```bash
  3630 ms  -[CLLocationManager init]
  3630 ms     | -[CLLocationManager initWithEffectiveBundleIdentifier:0x0 bundle:0x0]
  3634 ms  -[CLLocationManager setDelegate:0x14c9ab000]
  3641 ms  +[CLLocationManager authorizationStatus]
RET: 0x4
  3641 ms  Called from:
0x1031aa158 TelegramUI!+[TGLocationUtils requestWhenInUserLocationAuthorizationWithLocationManager:]
    0x10337e2c0 TelegramUI!-[TGLocationPickerController initWithContext:intent:]
    0x101ee93ac TelegramUI!0x1013ac
```

We see that `+[CLLocationManager authorizationStatus]` returned `0x4` ([CLAuthorizationStatus.authorizedWhenInUse](https://developer.apple.com/documentation/corelocation/clauthorizationstatus/authorizedwheninuse "CLAuthorizationStatus.authorizedWhenInUse")) and was called by `+[TGLocationUtils requestWhenInUserLocationAuthorizationWithLocationManager:]`. As we anticipated before, you might use this kind of information as an entry point when reverse engineering the app and from there get inputs (e.g. names of classes or methods) to keep feeding the dynamic analysis.

Next, there is a _visual_ way to inspect the status of some app permissions when using the iPhone/iPad by opening "Settings" and scrolling down until you find the app you're interested in. When clicking on it, this will open the "ALLOW APP_NAME TO ACCESS" screen. However, not all permissions might be displayed yet. You will have to trigger them in order to be listed on that screen.

<img src="Images/Chapters/0x06h/settings_allow_screen.png" width="100%" />

For example, in the previous example, the "Location" entry was not being listed until we triggered the permission dialogue for the first time. Once we did it, no matter if we allowed the access or not, the the "Location" entry will be displayed.
