---
title: Convert Plist Files to JSON
platform: ios
---

You can convert Plist files, such as `Info.plist` or `PrivacyInfo.xcprivacy` (also a Plist file despite the extension), to JSON format for easier readability and analysis.

### Using plutil

Use @MASTG-TOOL-0062 to convert any Plist files, such as `PrivacyInfo.xcprivacy`, to JSON format:

```console
plutil -convert json -o PrivacyInfo.xcprivacy.json SocialApp.app/PrivacyInfo.xcprivacy
```

### Using plistlib

Use Python's built-in @MASTG-TOOL-0136 module to convert any Plist files, such as `PrivacyInfo.xcprivacy`, to JSON format:

```python
import plistlib
import json

with open('SocialApp.app/PrivacyInfo.xcprivacy', 'rb') as fp:
    data = plistlib.load(fp)

with open('PrivacyInfo.json', 'w', encoding='utf-8') as fp:
    json.dump(data, fp, indent=2, ensure_ascii=False)
```

Which outputs:

```json
{
  "NSPrivacyAccessedAPITypes": [
    {
      "NSPrivacyAccessedAPIType": "NSPrivacyAccessedAPICategoryUserDefaults",
      "NSPrivacyAccessedAPITypeReasons": [
        "CA92.1",
        "1C8F.1",
        "C56D.1"
      ]
    },
    ...
  ],
  "NSPrivacyCollectedDataTypes": [
    {
      "NSPrivacyCollectedDataType": "NSPrivacyCollectedDataTypeName",
      "NSPrivacyCollectedDataTypeLinked": true,
      "NSPrivacyCollectedDataTypePurposes": [
        "NSPrivacyCollectedDataTypePurposeAppFunctionality",
        "NSPrivacyCollectedDataTypePurposeOther"
      ],
      "NSPrivacyCollectedDataTypeTracking": false
    },
    ...
  ],
  "NSPrivacyTracking": true,
  "NSPrivacyTrackingDomains": [
    "trk-v2.socialapp.com",
    "trk-v2.socialapp.us",
    ...
  ]
}
```

## Using IPSW

Use @MASTG-TOOL-0105 to convert any Plist files, such as `Info.plist`, to JSON format:

```bash
$ ipsw plist ./Info.plist
{
    "BuildMachineOSBuild": "23B74",
    "CFBundleDevelopmentRegion": "en",
    "CFBundleExecutable": "MASTestApp",
    "CFBundleIdentifier": "org.owasp.mastestapp.MASTestApp",
    "CFBundleInfoDictionaryVersion": "6.0",
    "CFBundleName": "MASTestApp",
    "CFBundlePackageType": "APPL",
    "CFBundleShortVersionString": "1.0",
    "CFBundleSupportedPlatforms": [
        "iPhoneOS"
    ],
    ...
}
```
