---
title: Obtaining a Developer Provisioning Profile
platform: ios
---

The _provisioning profile_ is a plist file signed by Apple, which adds your code-signing certificate to its list of accepted certificates on one or more devices. In other words, this represents Apple explicitly allowing your app to run for certain reasons, such as debugging on selected devices (development profile). The provisioning profile also includes the _entitlements_ granted to your app. The _certificate_ contains the private key you'll use to sign.

A valid provisioning profile can only be obtained from Apple. This means that you need a valid Apple account.

!!! info

    You can obtain a valid provisioning profile for both normal Apple accounts, and for Apple Developer accounts. There are two important differences between the two types:

    **Certificate expiration**

    - Apple account: Certificates expire 7 days after creation
    - Developer account: Certificates expire 1 year after creation

    **Wildcard certificates**

    - Apple account: Certificates are only valid for one Bundle Identifier. This Bundle Identifier has to be unique.
    - Developer account: Certificates can be wildcards, allowing you to keep the original Bundle Identifier

    An Apple Developer account costs $99 per year and is a nice-to-have due to the longer expiration, but not a requirement.

The steps below work for both a normal Apple account and an Apple Developer account, but do require a macOS host.

## Creating a signing identity

Install @MASTG-TOOL-0070 and create a new iOS application with any language and configuration. Set up the project to use automatic signing and deploy the application to your iOS device. During this flow, you will have to accept your Developer certificate on the device, as well as enable Developer mode.

After these steps, you can use the @MASTG-TOOL-0063 command to list your signing identities:

```bash
$ security find-identity -v -p codesigning
 1) 50034388646913B117AF1D6E51D9E045B77EA916 "Apple Development: MAS@owasp.org (LVGBSLUQB4)"
     1 valid identities found
```

Additionally, the provisioning profile is stored on your host in the `~/Library/Developer/Xcode/DerivedData` folder:

```bash
$ find  ~/Library/Developer/Xcode/DerivedData | grep embedded
/Users/MAS/Library/Developer/Xcode/DerivedData/apptest-aijwmhfiximgzkhcmnluxrscflyc/Build/Products/Debug-iphoneos/apptest.app/embedded.mobileprovision
```

This file can be copied to your local directory and can be used to sign any IPA file, even those with a different identifier.

```bash
cp /Users/MAS/Library/Developer/Xcode/DerivedData/apptest-aijwmhfiximgzkhcmnluxrscflyc/Build/Products/Debug-iphoneos/apptest.app/embedded.mobileprovision ./embedded.mobileprovision
```

## Inspecting the Provisioning Profile

Once you've obtained the provisioning profile, you can inspect its contents with the @MASTG-TOOL-0063 command. You'll find the entitlements granted to the app in the profile, along with the allowed certificates and devices.

```bash
$ security cms -D -i embedded.mobileprovision
```

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
    <dict>
        <key>AppIDName</key>
        <string>XC org mas testapp</string>
        <key>ApplicationIdentifierPrefix</key>
        <array>
            <string>QH868V5764</string>
        </array>
        <key>CreationDate</key>
        <date>2024-12-26T07:22:22Z</date>
        <key>Platform</key>
        <array>
            <string>iOS</string>
            <string>xrOS</string>
            <string>visionOS</string>
        </array>
        <key>IsXcodeManaged</key>
        <true/>
        <key>DeveloperCertificates</key>
        <array>
            <data>...SNIP...</data>
        </array>
        <key>DER-Encoded-Profile</key>
        <data>...SNIP...</data>
        <key>Entitlements</key>
        <dict>
            <key>application-identifier</key>
            <string>QH868V5764.org.mas.apptest</string>
            <key>keychain-access-groups</key>
            <array>
                <string>QH868V5764.*</string>
            </array>
            <key>get-task-allow</key>
            <true/>
            <key>com.apple.developer.team-identifier</key>
            <string>QH868V5764</string>
        </dict>
        <key>ExpirationDate</key>
        <date>2025-01-02T07:22:22Z</date>
        <key>Name</key>
        <string>iOS Team Provisioning Profile: org.mas.testapp</string>
        <key>ProvisionedDevices</key>
        <array>
            <string>...SNIP...</string>
        </array>
        <key>LocalProvision</key>
        <true/>
        <key>TeamIdentifier</key>
        <array>
            <string>QH868V5764</string>
        </array>
        <key>TeamName</key>
        <string>OWASP MAS</string>
        <key>TimeToLive</key>
        <integer>7</integer>
        <key>UUID</key>
        <string>...SNIP...</string>
        <key>Version</key>
        <integer>1</integer>
    </dict>
</plist>
```
