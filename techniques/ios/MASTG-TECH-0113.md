---
title: Software Composition Analysis (SCA) of iOS Dependencies
platform: ios
---

iOS has several dependency managers, where the most popular are:

- [Carthage](https://github.com/Carthage/Carthage),
- [CocoaPods](https://github.com/CocoaPods/CocoaPods) and
- [SwiftPM](https://github.com/swiftlang/swift-package-manager) (Swift Package Manager)

The dependencies will be integrated into the project during the build and compiled into the IPA, therefore we cannot scan the IPA file. Instead, tools like @MASTG-TOOL-0116 can be used to scan the files created by the dependency managers, which list the dependencies and their versions built into the iOS app. Once identified such tools will identify known vulnerabilities in the dependencies by comparing them to a vulnerability database (like the National Vulnerability Database, NVD).

In order to test for dependencies with known vulnerabilities, we need to retrieve the corresponding file of the dependency manager used:

- For Carthage it is the file `Cartfile.resolved`.
- For CocoaPods it is the file `*.podspec` or `Podfile.lock`
- For SwiftPM it is the file `Package.swift` or `Package.resolved`

When scanning with @MASTG-TOOL-0116 it is sufficient to scan the file of the dependency manager that is used.

Before we can run the scan, you will need to obtain an API key for NVD, which is used to retrieve the latest CVE information. The API Key to access the NVD API can be requested from <https://nvd.nist.gov/developers/request-an-api-key>.

To start a scan for a project using SwiftPM, execute the following command:

```bash
$ dependency-check --enableExperimental -f SARIF --nvdApiKey <YOUR-API-KEY> -s Package.resolved
```

The output will be a SARIF file, which can be viewed in @MASTG-TOOL-0118 by using the Sarif Viewer Plugin. If any known vulnerabilities were identified, it will list them and their CVE number and description.
