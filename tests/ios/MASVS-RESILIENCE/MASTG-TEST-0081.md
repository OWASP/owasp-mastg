---
masvs_v1_id:
- MSTG-CODE-1
masvs_v2_id:
- MASVS-RESILIENCE-2
platform: ios
title: Making Sure that the App Is Properly Signed
masvs_v1_levels:
- R
profiles: [R]
covered_by: [MASTG-TEST-0220]
status: deprecated
deprecation_note: New version available in MASTG V2
---

## Overview

## Static Analysis

You have to ensure that the app is [using the latest code signature format](https://developer.apple.com/documentation/xcode/using-the-latest-code-signature-format). You can retrieve the signing certificate information from the application's .app file with @MASTG-TOOL-0114. Codesign is used to create, check, and display code signatures, as well as inquire into the dynamic status of signed code in the system.

After you get the application's IPA file, re-save it as a ZIP file and decompress the ZIP file. Navigate to the Payload directory, where the application's .app file will be.

Execute the following `codesign` command to display the signing information:

```bash
$ codesign -dvvv YOURAPP.app
Executable=/Users/Documents/YOURAPP/Payload/YOURAPP.app/YOURNAME
Identifier=com.example.example
Format=app bundle with Mach-O universal (armv7 arm64)
CodeDirectory v=20200 size=154808 flags=0x0(none) hashes=4830+5 location=embedded
Hash type=sha256 size=32
CandidateCDHash sha1=455758418a5f6a878bb8fdb709ccfca52c0b5b9e
CandidateCDHash sha256=fd44efd7d03fb03563b90037f92b6ffff3270c46
Hash choices=sha1,sha256
CDHash=fd44efd7d03fb03563b90037f92b6ffff3270c46
Signature size=4678
Authority=iPhone Distribution: Example Ltd
Authority=Apple Worldwide Developer Relations Certification Authority
Authority=Apple Root CA
Signed Time=4 Aug 2017, 12:42:52
Info.plist entries=66
TeamIdentifier=8LAMR92KJ8
Sealed Resources version=2 rules=12 files=1410
Internal requirements count=1 size=176
```

There are various ways to distribute your app as described at [the Apple documentation](https://developer.apple.com/business/distribute/ "Apple Business"), which include using the App Store or via Apple Business Manager for custom or in-house distribution. In case of an in-house distribution scheme, make sure that no ad hoc certificates are used when the app is signed for distribution.
