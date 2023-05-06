---
masvs_v1_id:
- MSTG-CODE-2
masvs_v2_id:
- MASVS-RESILIENCE-4
platform: ios
title: Testing whether the App is Debuggable
masvs_v1_levels:
- R
---

## Overview

## Static Analysis

Inspect the app entitlements and check the value of `get-task-allow` key. If it is set to `true`, the app is debuggable.

Using codesign:

```bash
$ codesign -d --entitlements - iGoat-Swift.app

Executable=/Users/owasp/iGoat-Swift/Payload/iGoat-Swift.app/iGoat-Swift
[Dict]
    [Key] application-identifier
    [Value]
        [String] TNAJ496RHB.OWASP.iGoat-Swift
    [Key] com.apple.developer.team-identifier
    [Value]
        [String] TNAJ496RHB
    [Key] get-task-allow
    [Value]
        [Bool] true
    [Key] keychain-access-groups
    [Value]
        [Array]
            [String] TNAJ496RHB.OWASP.iGoat-Swift
````

Using ldid:

```xml
$ ldid -e iGoat-Swift.app/iGoat-Swift

<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>application-identifier</key>
    <string>TNAJ496RHB.OWASP.iGoat-Swift</string>
    <key>com.apple.developer.team-identifier</key>
    <string>TNAJ496RHB</string>
    <key>get-task-allow</key>
    <true/>
    <key>keychain-access-groups</key>
    <array>
        <string>TNAJ496RHB.OWASP.iGoat-Swift</string>
    </array>
</dict>
</plist>
```

## Dynamic Analysis

Check whether you can attach a debugger directly, using Xcode. Next, check if you can debug the app on a jailbroken device after Clutching it. This is done using the debug-server which comes from the BigBoss repository at Cydia.

Note: if the application is equipped with anti-reverse engineering controls, then the debugger can be detected and stopped.
