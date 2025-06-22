---
title: Extracting Entitlements from MachO Binaries
platform: ios
---

Several tools can be used to extract entitlements from MachO binaries on iOS. This is useful for security assessments, as entitlements can reveal permissions and capabilities granted to an app.

## Using @MASTG-TOOL-0129

Use rabin2 to extract entitlements from MachO binaries using `rabin2 -OC <binary>`:

```bash
rabin2 -OC MASTestApp
```

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
        <key>application-identifier</key>
        <string>AYRP7NNB54.org.owasp.mastestapp.MASTestApp-iOS</string>
        <key>com.apple.developer.team-identifier</key>
        <string>AYRP7NNB54</string>
        <key>get-task-allow</key>
        <true/>
</dict>
</plist>
```

## Using @MASTG-TOOL-0111

Use ldid to extract entitlements from MachO binaries. The `-e` flag is used to specify that entitlements should be extracted, and the `-A` flag is added to specify the desired architecture (`16777228:0`, which is `CPU_TYPE_ARM64:CPU_SUBTYPE_ARM64_ALL`):

```bash
ldid -e -A16777228:0 iGoat-Swift.app/iGoat-Swift

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

## Using @MASTG-TOOL-0105

Use ipsw to extract entitlements from MachO binaries using the `ipsw macho info -e` command:

```bash
ipsw macho info -e iGoat-Swift.app/iGoat-Swift
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

## Using @MASTG-TOOL-0114

Use `codesign` to extract entitlements from a MachO binary using `codesign -d --entitlements - <binary>`. Make sure to include the `-` as the argument for the `--entitlements` flag:

```bash
codesign -d --entitlements - iGoat-Swift.app/iGoat-Swift
```

```bash
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
