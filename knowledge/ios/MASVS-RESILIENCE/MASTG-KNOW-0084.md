---
masvs_category: MASVS-RESILIENCE
platform: ios
title: Jailbreak Detection
---

Jailbreak detection mechanisms are added to reverse engineering defense to make running the app on a jailbroken device more difficult. This blocks some of the tools and techniques reverse engineers like to use. Like most other types of defense, jailbreak detection is not very effective by itself, but scattering checks throughout the app's source code can improve the effectiveness of the overall anti-tampering scheme.

> You can learn more about Jailbreak/Root Detection in the research study ["Jailbreak/Root Detection Evasion Study on iOS and Android"](https://github.com/crazykid95/Backup-Mobile-Security-Report/blob/master/Jailbreak-Root-Detection-Evasion-Study-on-iOS-and-Android.pdf "Jailbreak/Root Detection Evasion Study on iOS and Android") by Dana Geist and Marat Nigmatullin.

## Common Jailbreak Detection Checks

Here we present three typical jailbreak detection techniques:

**File-based Checks:**

The app might be checking for files and directories typically associated with jailbreaks, such as:

```default
/Applications/Cydia.app
/Applications/FakeCarrier.app
/Applications/Icy.app
/Applications/IntelliScreen.app
/Applications/MxTube.app
/Applications/RockApp.app
/Applications/SBSettings.app
/Applications/WinterBoard.app
/Applications/blackra1n.app
/Library/MobileSubstrate/DynamicLibraries/LiveClock.plist
/Library/MobileSubstrate/DynamicLibraries/Veency.plist
/Library/MobileSubstrate/MobileSubstrate.dylib
/System/Library/LaunchDaemons/com.ikey.bbot.plist
/System/Library/LaunchDaemons/com.saurik.Cydia.Startup.plist
/bin/bash
/bin/sh
/etc/apt
/etc/ssh/sshd_config
/private/var/lib/apt
/private/var/lib/cydia
/private/var/mobile/Library/SBSettings/Themes
/private/var/stash
/private/var/tmp/cydia.log
/var/tmp/cydia.log
/usr/bin/sshd
/usr/libexec/sftp-server
/usr/libexec/ssh-keysign
/usr/sbin/sshd
/var/cache/apt
/var/lib/apt
/var/lib/cydia
/usr/sbin/frida-server
/usr/bin/cycript
/usr/local/bin/cycript
/usr/lib/libcycript.dylib
/var/log/syslog
```

**Checking File Permissions:**

The app might be trying to write to a location that's outside the application's sandbox. For instance, it may attempt to create a file in, for example, the `/private` directory. If the file is created successfully, the app can assume that the device has been jailbroken.

```swift
do {
    let pathToFileInRestrictedDirectory = "/private/jailbreak.txt"
    try "This is a test.".write(toFile: pathToFileInRestrictedDirectory, atomically: true, encoding: String.Encoding.utf8)
    try FileManager.default.removeItem(atPath: pathToFileInRestrictedDirectory)
    // Device is jailbroken
} catch {
    // Device is not jailbroken
}
```

**Checking Protocol Handlers:**

The app might be attempting to call well-known protocol handlers such as `cydia://` (available by default after installing @MASTG-TOOL-0047).

```swift
if let url = URL(string: "cydia://package/com.example.package"), UIApplication.shared.canOpenURL(url) {
    // Device is jailbroken
}
```

## Automated Jailbreak Detection Bypass

The quickest way to bypass common Jailbreak detection mechanisms is @MASTG-TOOL-0038. You can find the implementation of the jailbreak bypass in the [jailbreak.ts script](https://github.com/sensepost/objection/blob/master/agent/src/ios/jailbreak.ts "jailbreak.ts").

## Manual Jailbreak Detection Bypass

If the automated bypasses aren't effective you need to get your hands dirty and reverse engineer the app binaries until you find the pieces of code responsible for the detection and either patch them statically or apply runtime hooks to disable them.

**Step 1: Reverse Engineering:**

When you need to reverse engineer a binary looking for jailbreak detection, the most obvious way is to search for known strings, such as "jail" or "jailbreak". Note that this won't be always effective, especially when resilience measures are in place or simply when the the developer has avoided such obvious terms.

Example: Download the @MASTG-APP-0024, unzip it, load the main binary into @MASTG-TOOL-0073 and wait for the analysis to complete.

```sh
r2 -A ./DVIA-v2-swift/Payload/DVIA-v2.app/DVIA-v2
```

Now you can list the binary's symbols using the `is` command and apply a case-insensitive grep (`~+`) for the string "jail".

```sh
[0x1001a9790]> is~+jail
...
2230  0x001949a8 0x1001949a8 GLOBAL FUNC 0        DVIA_v2.JailbreakDetectionViewController.isJailbroken.allocator__Bool
7792  0x0016d2d8 0x10016d2d8 LOCAL  FUNC 0        +[JailbreakDetection isJailbroken]
...
```

As you can see, there's an instance method with the signature `-[JailbreakDetectionVC isJailbroken]`.

**Step 2: Dynamic Hooks:**

Now you can use Frida to bypass jailbreak detection by performing the so-called early instrumentation, that is, by replacing function implementation right at startup.

Use `frida-trace` on your host computer:

```bash
frida-trace -U -f /Applications/DamnVulnerableIOSApp.app/DamnVulnerableIOSApp  -m "-[JailbreakDetectionVC isJailbroken]"
```

This will start the app, trace calls to `-[JailbreakDetectionVC isJailbroken]`, and create a JavaScript hook for each matching element.
Open `./__handlers__/__JailbreakDetectionVC_isJailbroken_.js` with your favouritte editor and edit the `onLeave` callback function. You can simply replace the return value using `retval.replace()` to always return `0`:

```javascript
onLeave: function (log, retval, state) {
    console.log("Function [JailbreakDetectionVC isJailbroken] originally returned:"+ retval);
    retval.replace(0);
    console.log("Changing the return value to:"+retval);
}
```

This will provide the following output:

```bash
$ frida-trace -U -f /Applications/DamnVulnerableIOSApp.app/DamnVulnerableIOSApp  -m "-[JailbreakDetectionVC isJailbroken]:"

Instrumenting functions...                                           `...
-[JailbreakDetectionVC isJailbroken]: Loaded handler at "./__handlers__/__JailbreakDetectionVC_isJailbroken_.js"
Started tracing 1 function. Press Ctrl+C to stop.

Function [JailbreakDetectionVC isJailbroken] originally returned:0x1
Changing the return value to:0x0
```
