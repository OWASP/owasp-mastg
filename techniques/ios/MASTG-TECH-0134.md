---
title: Software Composition Analysis (SCA) of iOS Dependencies by Scanning Package Manager Artifacts
platform: ios
---

iOS has several dependency managers, where the most popular are:

- [Carthage](https://github.com/Carthage/Carthage),
- [CocoaPods](https://github.com/CocoaPods/CocoaPods) and
- [SwiftPM](https://github.com/swiftlang/swift-package-manager) (Swift Package Manager)

The dependencies are integrated into the project during build and compiled into the IPA. The version information of the dependencies may be stripped out during compilation, so we cannot scan the IPA file, but we can scan the artifacts produced by the dependency managers.

Tools such as @MASTG-TOOL-0131 can be used to scan the files created by all three dependency managers, which list the dependencies as [Common Platform Enumeration (CPE)](https://nvd.nist.gov/products/cpe "CPE") and their versions, which will be included in the iOS app. Once identified, such tools will search for known vulnerabilities, so called [CVE's (Common Vulnerability and Exposure)](https://cve.mitre.org/ "CVE") in the dependencies by checking them against a vulnerability database such as the National Vulnerability Database (NVD).

> Note that @MASTG-TOOL-0131 does support [Carthage](https://jeremylong.github.io/DependencyCheck/analyzers/carthage.html), [CocoaPods](https://jeremylong.github.io/DependencyCheck/analyzers/cocoapods.html) and [SwiftPM](https://jeremylong.github.io/DependencyCheck/analyzers/swift.html), but the analyzers are considered experimental. While this analyzer may be useful and provide valid results more testing must be completed to ensure that the false negative/positive rates are acceptable.

In order to test with @MASTG-TOOL-0131, we need to retrieve the corresponding file of the dependency manager used:

- For Carthage it is the file `Cartfile.resolved`.
- For CocoaPods it is the file `*.podspec` or `Podfile.lock`
- For SwiftPM it is the file `Package.swift` or `Package.resolved`

Keep in mind that developers may use more than one dependency manager and you might need to execute therefore more than one scan. When scanning with @MASTG-TOOL-0131 it is sufficient to scan the file created by the dependency manager, you don't need access to the whole Xcode project or source code.

Before we can run the scan, you will need to obtain an API key for NVD, which is used to retrieve the latest CVE information. The API Key to access the NVD API can be requested from <https://nvd.nist.gov/developers/request-an-api-key>.

- To start a scan for a project using SwiftPM, execute the following command to scan the `Package.Swift` or `Package.resolved`:

```bash
$ dependency-check --enableExperimental -f SARIF --nvdApiKey <YOUR-API-KEY> -s Package.resolved
```

- To start a scan for a project using CocoaPods, execute the following command to scan the `Podfile.lock` or `*.podspec`:

```bash
$ dependency-check --enableExperimental -f SARIF --nvdApiKey <YOUR-API-KEY> -s Podfile.lock
```

- To start a scan for a project using Carthage, execute the following command to scan the `Cartfile.resolved.`:

```bash
$ dependency-check --enableExperimental -f SARIF --nvdApiKey <YOUR-API-KEY> -s Cartfile.resolved
```

The output is always a SARIF file which can be viewed using the Sarif viewer plugin in @MASTG-TOOL-0133. If any known vulnerabilities are found, they will be listed with their CVE number and description.

You can only scan one file at at time. If you are scanning for CocoaPods or Carthage, you can use the same command again, but scan the corresponding dependency manager file instead.
