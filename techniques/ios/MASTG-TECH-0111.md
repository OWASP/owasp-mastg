---
title: Extracting Entitlements from MachO Binaries
platform: ios
---

To extract the entitlements from a MachO binary, the following tools can be used:

- @MASTG-TOOL-0111
- @MASTG-TOOL-0105
- @MASTG-TOOL-0101

The following examples use these tools on the main binary of @MASTG-APP-0028, which contains two architectures.

## ldid

The entitlements can be extracted using `ldid -e <binary>`. The `-A` flag is added to specify the desired architecture (16777228:0, which is CPU_TYPE_ARM64:CPU_SUBTYPE_ARM64_ALL):

```bash
$ldid -e -A16777228:0 iGoat-Swift.app/iGoat-Swift
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

## ipsw

The entitlements can be extracted using `ipsw macho info -e <binary>`. The `-a` flag is added to specify the desired architecture:

```bash
$ ipsw macho info -e iGoat-Swift.app/iGoat-Swift -a arm64
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

## codesign

The entitlements can be extracted using `codesign -d --entitlements - <binary>`. Make sure to include the `-` as the argument for the `--entitlements` flag:

```bash
$ codesign -d --entitlements - iGoat-Swift.app/iGoat-Swift
```

```code
Executable=/Users/owasp/iGoat/Payload/iGoat-Swift.app/iGoat-Swift
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

```
