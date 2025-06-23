---
masvs_v1_id:
- MSTG-CODE-2
masvs_v2_id:
- MASVS-RESILIENCE-4
platform: ios
title: Testing whether the App is Debuggable
masvs_v1_levels:
- R
profiles: [R]
status: deprecated
covered_by: [MASTG-TEST-0261]
deprecation_note: New version available in MASTG V2
---

## Overview

## Static Analysis

Extract the entitlements from the app (@MASTG-TECH-0111) and check the value of the `get-task-allow` key. If it is set to `true`, the app is debuggable.

```bash
$ ldid -e iGoat-Swift.app/iGoat-Swift
```

```xml
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

Check whether you can attach a debugger directly, as explained in @MASTG-TECH-0084.

Note: if the application is equipped with anti-reverse engineering controls, then the debugger can be detected and stopped.
