---
title: codesign
platform: ios
source: https://www.unix.com/man-page/osx/1/codesign/
alternatives:
- MASTG-TOOL-0102
- MASTG-TOOL-0117
---

The codesign tool is primarily used to create, verify, and display code signatures, and to query the dynamic status of signed code in the system. Although Xcode typically automates the process of signing code during builds and before distribution, there are scenarios where manual intervention with codesign is required. This can include inspecting or verifying the details of an app's code signature, or manually re-signing an app. For more detailed tasks such as these, you can use the codesign command line tool directly, as described in Apple's Code Signing Guide.

Learn more:

- ["Examining a Code Signature"](https://developer.apple.com/library/archive/documentation/Security/Conceptual/CodeSigningGuide/Procedures/Procedures.html#//apple_ref/doc/uid/TP40005929-CH4-SW10)
- ["Signing Code Manually"](https://developer.apple.com/library/archive/documentation/Security/Conceptual/CodeSigningGuide/Procedures/Procedures.html#//apple_ref/doc/uid/TP40005929-CH4-SW3) in Apple's Code Signing Guide
- [Using the latest code signature format](https://developer.apple.com/documentation/xcode/using-the-latest-code-signature-format)
- [codesign manpage](https://www.unix.com/man-page/osx/1/codesign/)
- [codesign source code](https://github.com/apple-oss-distributions/Security/blob/main/SecurityTool/sharedTool/codesign.c)
