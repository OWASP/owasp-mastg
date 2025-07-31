---
masvs_category: MASVS-CODE
platform: ios
title: Debuggable Apps
---

Apps can be made debuggable (@MASTG-TECH-0031) by adding the [`get-task-allow`](https://developer.apple.com/documentation/security/notarizing_macos_software_before_distribution/resolving_common_notarization_issues "Resolving common notarization issues") key to the app entitlements file and setting it to `true`.

While debugging is a useful feature when developing an app, it has to be turned off before releasing apps to the App Store or within an enterprise program. To do that you need to determine the mode in which your app is to be generated to check the flags in the environment:

- Select the build settings of the project
- Under 'Apple LVM - Preprocessing' and 'Preprocessor Macros', make sure 'DEBUG' or 'DEBUG_MODE' is not selected (Objective-C)
- Make sure that the "Debug executable" option is not selected.
- Or in the 'Swift Compiler - Custom Flags' section / 'Other Swift Flags', make sure the '-D DEBUG' entry does not exist.
