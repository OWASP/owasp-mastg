---
title: dependency-check
platform: generic
source: https://github.com/jeremylong/DependencyCheck
---

[Dependency-Check](https://github.com/jeremylong/DependencyCheck) is a Software Composition Analysis (SCA) tool that attempts to detect publicly disclosed vulnerabilities contained within a project's dependencies.

Limitations for SCA tools are, that they will usually fail to scan an IPA or APK, due to 2 main reasons:

- **Transformed format**: The libraries are no longer in their original format but are part of the app binaries compiled code format. For example an Android app will not contain the 3rd party JAR files in the APK, as they part of the compiled DEX files.
- **Lack of metadata**: Information such as the library version or name is stripped or altered when building the mobile app.

Therefore, for iOS, the files generated by dependency managers (such as Podfile for CocoaPods) that list the dependencies used in an app are scanned, or for Android, the scan is performed at build time using Dependency-Check.