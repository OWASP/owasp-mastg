---
title: dependency-check
platform: generic
source: https://github.com/jeremylong/DependencyCheck
---

[Dependency-Check](https://github.com/jeremylong/DependencyCheck) is a Software Composition Analysis (SCA) tool that attempts to detect publicly disclosed vulnerabilities contained within a project's dependencies.

However, SCA tools like Dependency-Check have their limitations. For example, they usually fail to scan IPA or APK files. There are two main reasons for this:

- **Transformed format**: The libraries are no longer in their original format, but rather, they are part of the app's compiled binary code. For instance, an Android app does not contain third-party JAR files in the APK because they are part of the compiled DEX files.
- **Lack of metadata**: Information such as the library version or name is often stripped or altered when building the mobile app.

Therefore, Dependency-Check is best used in a gray-box environment where the source code or at least the build configuration files are available. In this case, the tool can analyze the build configuration files to identify dependencies and their versions. For example:

- For iOS, the `Podfile` for CocoaPods or `Cartfile` for Carthage can be scanned to identify the dependencies used in the app.
- For Android, scan the `build.gradle` files to identify the dependencies used in the app.
