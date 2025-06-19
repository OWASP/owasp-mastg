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
                  <string>da-an-v3.socialappv.com</string>
                  <string>da-an-v3-va.socialappv.com</string>
                  <string>da-an-v3-sg.socialappv.com</string>
                  <string>da-an-v3-i18n.socialappv.com</string>
                  <string>da-an-v3.socialappv.us</string>
                  <string>da-an-v3-ttp2.socialappv.us</string>
                  <string>da-an-v3.socialappv.eu</string>
                  <string>da-an-v3-ru.socialappv.com</string>
          </array>
  </dict>
  </plist>
  ```

This `PrivacyInfo.xcprivacy` file contains:

- **NSPrivacyAccessedAPITypes**: Lists the APIs accessed by the app along with their reasons for access. In this case:
    - `NSPrivacyAccessedAPICategoryUserDefaults`: Accessed for reasons CA92.1, 1C8F.1, C56D.1
    - `NSPrivacyAccessedAPICategoryActiveKeyboards`: Accessed for reason 54BD.1
    - This indicates that the app uses `UserDefaults` and interacts with active keyboards for [specific reasons](https://developer.apple.com/documentation/bundleresources/app-privacy-configuration/nsprivacyaccessedapitypes/nsprivacyaccessedapitypereasons).
- **NSPrivacyCollectedDataTypes**: Lists the types of data collected by the app, whether they are linked to user identity, their purposes, and whether they are used for tracking. In this case:
    - `NSPrivacyCollectedDataTypeName`: Linked, with purposes including App Functionality and Other.
    - `NSPrivacyCollectedDataTypeOtherDiagnosticData`: Linked, with purposes including Analytics, App Functionality, and Other.
    - This indicates that the app collects user name and other diagnostic data for [specific purposes](https://developer.apple.com/documentation/bundleresources/app-privacy-configuration/nsprivacycollecteddatatypes/nsprivacycollecteddatatypepurposes).
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

Benefits include readable output, standard JSON tooling, and concise selection syntax. Caveats are that dates and raw data blobs become strings, numeric precision may shift, comments and key ordering are lost. Consider Python's [plistlib](https://docs.python.org/3/library/plistlib.html) if you need to preserve plist-specific types.

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

Use `PlistBuddy` to read and manipulate plist files directly without converting them to JSON, including `PrivacyInfo.xcprivacy`.

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
