---
masvs_v1_id:
- MSTG-CODE-5
masvs_v2_id:
- MASVS-CODE-3
platform: ios
title: Checking for Weaknesses in Third Party Libraries
masvs_v1_levels:
- L1
- L2
profiles: [L1, L2]
status: deprecated
covered_by: [MASTG-TEST-0273, MASTG-TEST-0275]
deprecation_note: New version available in MASTG V2
---

## Overview

## Static Analysis

### Detecting vulnerabilities of third party libraries

In order to ensure that the libraries used by the apps are not carrying vulnerabilities, one can best check the dependencies installed by CocoaPods or Carthage.

#### Swift Package Manager

In case [Swift Package Manager](https://swift.org/package-manager "Swift Package Manager on Swift.org") is used for managing third party dependencies, the following steps can be taken to analyze the third party libraries for vulnerabilities:

First, at the root of the project, where the Package.swift file is located, type

```bash
swift build
```

Next, check the file Package.resolved for the actual versions used and inspect the given libraries for known vulnerabilities.

You can utilize the [OWASP Dependency-Check](https://owasp.org/www-project-dependency-check/ "OWASP Dependency-Check")'s experimental [Swift Package Manager Analyzer](https://jeremylong.github.io/DependencyCheck/analyzers/swift.html "dependency-check - SWIFT Package Manager Analyzer") to identify the [Common Platform Enumeration (CPE)](https://nvd.nist.gov/products/cpe "CPE") naming scheme of all dependencies and any corresponding [Common Vulnerability and Exposure (CVE)](https://cve.mitre.org/ "CVE") entries. Scan the application's Package.swift file and generate a report of known vulnerable libraries with the following command:

```bash
dependency-check  --enableExperimental --out . --scan Package.swift
```

#### CocoaPods

In case [CocoaPods](https://cocoapods.org "CocoaPods.org") is used for managing third party dependencies, the following steps can be taken to analyze the third party libraries for vulnerabilities.

First, at the root of the project, where the Podfile is located, execute the following commands:

```bash
sudo gem install cocoapods
pod install
```

Next, now that the dependency tree has been built, you can create an overview of the dependencies and their versions by running the following commands:

```bash
sudo gem install cocoapods-dependencies
pod dependencies
```

The result of the steps above can now be used as input for searching different vulnerability feeds for known vulnerabilities.

> Note:
>
> 1. If the developer packs all dependencies in terms of its own support library using a .podspec file, then this .podspec file can be checked with the experimental CocoaPods podspec checker.
> 2. If the project uses CocoaPods in combination with Objective-C, SourceClear can be used.
> 3. Using CocoaPods with HTTP-based links instead of HTTPS might allow for [Machine-in-the-Middle (MITM)](../../../Document/0x04f-Testing-Network-Communication.md#intercepting-network-traffic-through-mitm) attacks during the download of the dependency, allowing an attacker to replace (parts of) the library with other content. Therefore, always use HTTPS.

You can utilize the [OWASP Dependency-Check](https://owasp.org/www-project-dependency-check/ "OWASP Dependency-Check")'s experimental [CocoaPods Analyzer](https://jeremylong.github.io/DependencyCheck/analyzers/cocoapods.html "dependency-check - CocoaPods Analyzer")
to identify the [Common Platform Enumeration (CPE)](https://nvd.nist.gov/products/cpe "CPE") naming scheme of all dependencies and any corresponding [Common Vulnerability and Exposure (CVE)](https://cve.mitre.org/ "CVE") entries. Scan the application's \*.podspec and/or Podfile.lock files and generate a report of known vulnerable libraries with the following command:

```bash
dependency-check  --enableExperimental --out . --scan Podfile.lock
```

#### Carthage

In case [Carthage](https://github.com/Carthage/Carthage "Carthage on GitHub") is used for third party dependencies, then the following steps can be taken to analyze the third party libraries for vulnerabilities.

First, at the root of the project, where the Cartfile is located, type

```bash
brew install carthage
carthage update --platform iOS
```

Next, check the Cartfile.resolved for actual versions used and inspect the given libraries for known vulnerabilities.

> Note, at the time of writing this chapter, there is no automated support for Carthage based dependency analysis known to the authors. At least, this feature was already requested for the OWASP DependencyCheck tool but not yet implemented (see the [GitHub issue](https://github.com/jeremylong/DependencyCheck/issues/962 "Add Carthage Analyze for Swift")).

### Discovered library vulnerabilities

When a library is found to contain vulnerabilities, then the following reasoning applies:

- Is the library packaged with the application? Then check whether the library has a version in which the vulnerability is patched. If not, check whether the vulnerability actually affects the application. If that is the case or might be the case in the future, then look for an alternative which provides similar functionality, but without the vulnerabilities.
- Is the library not packaged with the application? See if there is a patched version in which the vulnerability is fixed. If this is not the case, check if the implications of the vulnerability for the build process. Could the vulnerability impede a build or weaken the security of the build-pipeline? Then try looking for an alternative in which the vulnerability is fixed.

In case frameworks are added manually as linked libraries:

1. Open the xcodeproj file and check the project properties.
2. Go to the tab **Build Phases** and check the entries in **Link Binary With Libraries** for any of the libraries. See earlier sections on how to obtain similar information using @MASTG-TOOL-0035.

In the case of copy-pasted sources: search the header files (in case of using Objective-C) and otherwise the Swift files for known method names for known libraries.

Next, note that for hybrid applications, you will have to check the JavaScript dependencies with [RetireJS](https://retirejs.github.io/retire.js/ "RetireJS"). Similarly for Xamarin, you will have to check the C# dependencies.

Last, if the application is a high-risk application, you will end up vetting the library manually. In that case there are specific requirements for native code, which are similar to the requirements established by the MASVS for the application as a whole. Next to that, it is good to vet whether all best practices for software engineering are applied.

## Dynamic Analysis

The dynamic analysis of this section comprises of two parts: the actual license verification and checking which libraries are involved in case of missing sources.

It need to be validated whether the copyrights of the licenses have been adhered to. This often means that the application should have an `about` or `EULA` section in which the copy-right statements are noted as required by the license of the third party library.

### Listing Application Libraries

When performing app analysis, it is important to also analyze the app dependencies (usually in form of libraries or so-called iOS Frameworks) and ensure that they don't contain any vulnerabilities. Even when you don't have the source code, you can still identify some of the app dependencies using tools like @MASTG-TOOL-0038, @MASTG-TOOL-0035 or the `otool -L` command. Objection is the recommended tool, since it provides the most accurate results and it is easy to use. It contains a module to work with iOS Bundles, which offers two commands: `list_bundles` and `list_frameworks`.

The `list_bundles` command lists all of the application's bundles that are not related to Frameworks. The output contains executable name, bundle id, version of the library and path to the library.

```bash
...itudehacks.DVIAswiftv2.develop on (iPhone: 13.2.3) [usb] # ios bundles list_bundles
Executable    Bundle                                       Version  Path
------------  -----------------------------------------  ---------  -------------------------------------------
DVIA-v2       com.highaltitudehacks.DVIAswiftv2.develop          2  ...-1F0C-4DB1-8C39-04ACBFFEE7C8/DVIA-v2.app
CoreGlyphs    com.apple.CoreGlyphs                               1  ...m/Library/CoreServices/CoreGlyphs.bundle
```

The `list_frameworks` command lists all of the application's bundles that represent Frameworks.

```bash
...itudehacks.DVIAswiftv2.develop on (iPhone: 13.2.3) [usb] # ios bundles list_frameworks
Executable      Bundle                                     Version    Path
--------------  -----------------------------------------  ---------  -------------------------------------------
Bolts           org.cocoapods.Bolts                        1.9.0      ...8/DVIA-v2.app/Frameworks/Bolts.framework
RealmSwift      org.cocoapods.RealmSwift                   4.1.1      ...A-v2.app/Frameworks/RealmSwift.framework
                                                                      ...ystem/Library/Frameworks/IOKit.framework
...
```
