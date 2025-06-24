---
title: Analyzing PrivacyInfo.xcprivacy Files
platform: ios
---

Once you've obtained a privacy manifest as indicated in @MASTG-TECH-0136, you can proceed to analyze it.

Let's use the `SocialApp.app/PrivacyInfo.xcprivacy` file as an example.

??? note "SocialApp.app/PrivacyInfo.xcprivacy"

    ```xml
    <?xml version="1.0" encoding="UTF-8"?>
    <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
    <plist version="1.0">
    <dict>
            <key>NSPrivacyAccessedAPITypes</key>
            <array>
                    <dict>
                            <key>NSPrivacyAccessedAPIType</key>
                            <string>NSPrivacyAccessedAPICategoryUserDefaults</string>
                            <key>NSPrivacyAccessedAPITypeReasons</key>
                            <array>
                                    <string>CA92.1</string>
                                    <string>1C8F.1</string>
                                    <string>C56D.1</string>
                            </array>
                    </dict>
                    <dict>
                            <key>NSPrivacyAccessedAPIType</key>
                            <string>NSPrivacyAccessedAPICategoryActiveKeyboards</string>
                            <key>NSPrivacyAccessedAPITypeReasons</key>
                            <array>
                                    <string>54BD.1</string>
                            </array>
                    </dict>
            </array>
            <key>NSPrivacyCollectedDataTypes</key>
            <array>
                    <dict>
                            <key>NSPrivacyCollectedDataType</key>
                            <string>NSPrivacyCollectedDataTypeName</string>
                            <key>NSPrivacyCollectedDataTypeLinked</key>
                            <true/>
                            <key>NSPrivacyCollectedDataTypePurposes</key>
                            <array>
                                    <string>NSPrivacyCollectedDataTypePurposeAppFunctionality</string>
                                    <string>NSPrivacyCollectedDataTypePurposeOther</string>
                            </array>
                            <key>NSPrivacyCollectedDataTypeTracking</key>
                            <false/>
                    </dict>
                    <dict>
                            <key>NSPrivacyCollectedDataType</key>
                            <string>NSPrivacyCollectedDataTypeOtherDiagnosticData</string>
                            <key>NSPrivacyCollectedDataTypeLinked</key>
                            <true/>
                            <key>NSPrivacyCollectedDataTypePurposes</key>
                            <array>
                                    <string>NSPrivacyCollectedDataTypePurposeAnalytics</string>
                                    <string>NSPrivacyCollectedDataTypePurposeAppFunctionality</string>
                                    <string>NSPrivacyCollectedDataTypePurposeOther</string>
                            </array>
                            <key>NSPrivacyCollectedDataTypeTracking</key>
                            <false/>
                    </dict>
            </array>
            <key>NSPrivacyTracking</key>
            <true/>
            <key>NSPrivacyTrackingDomains</key>
            <array>
                    <string>trk-v2.socialapp.com</string>
                    <string>trk-v2.socialapp.us</string>
                    <string>trk-v2.socialapp.eu</string>
            </array>
    </dict>
    </plist>
    ```

This `PrivacyInfo.xcprivacy` file contains:

- **NSPrivacyAccessedAPITypes**: Lists the [APIs types accessed](https://developer.apple.com/documentation/bundleresources/app-privacy-configuration/nsprivacyaccessedapitypes/nsprivacyaccessedapitype) by the app along with their [reasons for access](https://developer.apple.com/documentation/bundleresources/app-privacy-configuration/nsprivacyaccessedapitypes/nsprivacyaccessedapitypereasons). In this case:
    - `NSPrivacyAccessedAPICategoryUserDefaults`: `UserDefaults` accessed for reasons `CA92.1`, `1C8F.1`, `C56D.1`.
    - `NSPrivacyAccessedAPICategoryActiveKeyboards`: interaction with active keyboards accessed for reason `54BD.1`.
- **NSPrivacyCollectedDataTypes**: Lists the types of data collected by the app and the [specific purposes](https://developer.apple.com/documentation/bundleresources/app-privacy-configuration/nsprivacycollecteddatatypes/nsprivacycollecteddatatypepurposes). It also indicates whether the collected data is [linked to the user's identity](https://developer.apple.com/documentation/bundleresources/app-privacy-configuration/nsprivacycollecteddatatypes/nsprivacycollecteddatatypelinked) (`NSPrivacyCollectedDataTypeLinked`) and whether it is [used for tracking purposes](https://developer.apple.com/documentation/bundleresources/app-privacy-configuration/nsprivacycollecteddatatypes/nsprivacycollecteddatatypetracking) (`NSPrivacyCollectedDataTypeTracking`). In this case:
    - `NSPrivacyCollectedDataTypeName`: collects the user name with purposes including "App Functionality" and "Other" (linked to the user identity but not used for tracking).
    - `NSPrivacyCollectedDataTypeOtherDiagnosticData`: collects other diagnostic data for purposes including "Analytics", "App Functionality", and "Other" (linked to the user identity but not used for tracking).
- **NSPrivacyTracking**: Indicates that SocialApp uses data for tracking as defined under the App Tracking Transparency framework.
- **NSPrivacyTrackingDomains**: Lists the domains used for tracking purposes, which in this case includes various SocialApp-related domains.

You can use several tools and parsers to read and analyze these files programmatically.

## Using jq

If you convert the `PrivacyInfo.xcprivacy` file to JSON format as described in @MASTG-TECH-0138, you can use jq to make queries.

For example, to extract all `NSPrivacyAccessedAPITypeReasons` for each `NSPrivacyAccessedAPIType`:

```console
cat SocialApp.app/PrivacyInfo.json | jq '.NSPrivacyAccessedAPITypes[] | {api: .NSPrivacyAccessedAPIType, reasons: .NSPrivacyAccessedAPITypeReasons}'
```

Which outputs (truncated for readability):

```json
{
  "api": "NSPrivacyAccessedAPICategoryUserDefaults",
  "reasons": [
    "CA92.1",
    "1C8F.1",
    "C56D.1"
  ]
}
{
  "api": "NSPrivacyAccessedAPICategorySystemBootTime",
  "reasons": [
    "35F9.1"
  ]
}
...
```

Benefits include readable output, standard JSON tooling, and concise selection syntax. Caveats are that dates and raw data blobs become strings, numeric precision may shift, and comments and key ordering are lost. Consider Python's @MASTG-TOOL-0136 module if you need to preserve plist-specific types.

## Using plistlib

Use Python's built-in `plistlib` module to read and manipulate plist files, including `PrivacyInfo.xcprivacy`.

For example, to extract the `NSPrivacyAccessedAPITypeReasons` for each `NSPrivacyAccessedAPIType`:

```python
import plistlib
import json

# load the .xcprivacy plist
with open('SocialApp.app/PrivacyInfo.xcprivacy', 'rb') as fp:
    data = plistlib.load(fp)

# extract and print each API and its reasons in JSON
for item in data.get('NSPrivacyAccessedAPITypes', []):
    api = item.get('NSPrivacyAccessedAPIType')
    reasons = item.get('NSPrivacyAccessedAPITypeReasons')
    print(json.dumps({'api': api, 'reasons': reasons}, ensure_ascii=False))
```

The output is (truncated for readability):

```json
{"api": "NSPrivacyAccessedAPICategoryUserDefaults", "reasons": ["CA92.1", "1C8F.1", "C56D.1"]}
{"api": "NSPrivacyAccessedAPICategorySystemBootTime", "reasons": ["35F9.1"]}
...
```

## Using PlistBuddy

Use @MASTG-TOOL-0135 to read and manipulate plist files directly without converting them to JSON, including `PrivacyInfo.xcprivacy`.

For example, you can read `NSPrivacyAccessedAPITypes` using the following command:

```console
/usr/libexec/PlistBuddy -c "Print NSPrivacyAccessedAPITypes" ./SocialApp.app/PrivacyInfo.xcprivacy
Array {
    Dict {
        NSPrivacyAccessedAPIType = NSPrivacyAccessedAPICategoryUserDefaults
        NSPrivacyAccessedAPITypeReasons = Array {
            CA92.1
            1C8F.1
            C56D.1
        }
    }
    ...
}
```

You can dive deeper into the file to extract more specific information. For example, you can get the `NSPrivacyAccessedAPITypeReasons` of the first `NSPrivacyAccessedAPITypes` element (index `0`) this way:

```console
/usr/libexec/PlistBuddy -c "Print NSPrivacyAccessedAPITypes:0:NSPrivacyAccessedAPITypeReasons" ./SocialApp.app/PrivacyInfo.xcprivacy

Array {
    CA92.1
    1C8F.1
    C56D.1
}
```
