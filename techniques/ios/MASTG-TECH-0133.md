---
title: Software Composition Analysis (SCA) of iOS Dependencies by Scanning Package Manager Artifacts
platform: ios
---

iOS has several dependency managers, where the most popular are:

- [Carthage](https://github.com/Carthage/Carthage),
- [CocoaPods](https://github.com/CocoaPods/CocoaPods) and
- [SwiftPM (Swift Package Manager)](https://github.com/swiftlang/swift-package-manager)

The dependencies are integrated into the project during the build process and are then compiled into the IPA file. However, the version information of the dependencies may be stripped out during compilation, which means we cannot scan the IPA file. Fortunately, we can scan the artifacts produced by the dependency managers.

Tools such as @MASTG-TOOL-0131 can scan files created by all three dependency managers. These files list dependencies as [Common Platform Enumeration (CPE)](https://nvd.nist.gov/products/cpe "CPE") and their versions. The CPE will be included in the iOS app. These tools then search for known vulnerabilities, or [CVEs (Common Vulnerability and Exposure)](https://cve.mitre.org/ "CVE"), in the dependencies by checking them against a vulnerability database, such as the National Vulnerability Database (NVD).

> Note that @MASTG-TOOL-0131 supports [Carthage](https://jeremylong.github.io/DependencyCheck/analyzers/carthage.html), [CocoaPods](https://jeremylong.github.io/DependencyCheck/analyzers/cocoapods.html) and [SwiftPM](https://jeremylong.github.io/DependencyCheck/analyzers/swift.html), but these analyzers are considered experimental. While these analyzers may be useful and provide valid results, more testing must be completed to ensure that the false negative/positive rates are acceptable.

To test with @MASTG-TOOL-0131, we need to retrieve the dependency manager's corresponding file:

- For Carthage it is the file `Cartfile.resolved`.
- For CocoaPods it is the file `*.podspec` or `Podfile.lock`
- For SwiftPM it is the file `Package.swift` or `Package.resolved`

Keep in mind that developers may use more than one dependency manager, so you may need to perform more than one scan. When scanning with @MASTG-TOOL-0131, scanning the file created by the dependency manager is sufficient; you don't need access to the entire Xcode project or source code.

Before running the scan, obtain an API key for NVD. This key is used to retrieve the latest CVE information. You can request the API key to access the NVD API from <https://nvd.nist.gov/developers/request-an-api-key>.

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

The output is always a SARIF file which can be viewed using the Sarif viewer plugin in @MASTG-TOOL-0133. Any known vulnerabilities found will be listed with their CVE number and description.

You can only scan one file at a time. When scanning for CocoaPods or Carthage, use the same command but scan the corresponding dependency manager file.
