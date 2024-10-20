---
title: Software Composition Analysis (SCA) of iOS Dependencies
platform: ios
---

iOS has several dependency managers, where the most popular are:

- [Carthage](https://github.com/Carthage/Carthage),
- [CocoaPods](https://github.com/CocoaPods/CocoaPods) and
- [SwiftPM](https://github.com/swiftlang/swift-package-manager) (Swift Package Manager)

The dependencies will be integrated into the project during the build and compiled into the IPA, therefore we cannot scan the IPA file.

Depending on the Package Manager used, you have different options to execute a scan. Keep in mind that developers may use more than one dependency manager and you might need to execute therefore more than one scan.

## SwiftPM

@MASTG-TOOL-0119 can be used to create a so called Software Bill of Material (SBOM) in the CycloneDX format. Navigate to the root directory of the Xcode project you want to scan and execute the following command:

```bash
$ cdxgen -o sbom.json
```

The created SBOM file need to be Base64 encoded and can then be uploaded to @MASTG-TOOL-0117 for analysis:

```bash
$ cat sbom.json | base64
$ curl -X "PUT" "http://localhost:8081/api/v1/bom" \
     -H 'Content-Type: application/json' \
     -H 'X-API-Key: <YOUR API KEY>>' \
     -d $'{
  "project": "<YOUR PROJECT ID>",
  "bom": "<BASE64-ENCODED SBOM>"
  }'
```

Go to frontend of dependency-check, which is <http://localhost:8080>, if you are using the default settings of the dependency-track docker container. Open the project you uploaded the SBOM to and you can verify if there are any vulnerable dependencies.

> Note: Transitive dependencies are not supported by @MASTG-TOOL-0117 for [SwiftPM](https://cyclonedx.github.io/cdxgen/#/PROJECT_TYPES).

## Carthage, CocoaPods and SwiftPM

Tools like @MASTG-TOOL-0116 can be used to scan the files created by all 3 dependency managers, which list the dependencies and their versions built into the iOS app. Once identified such tools will identify known vulnerabilities in the dependencies by comparing them to a vulnerability database (like the National Vulnerability Database, NVD).

> Note that @MASTG-TOOL-0116 does support [Carthage](https://jeremylong.github.io/DependencyCheck/analyzers/carthage.html), [CocoaPods](https://jeremylong.github.io/DependencyCheck/analyzers/cocoapods.html) and [SwiftPM](https://jeremylong.github.io/DependencyCheck/analyzers/swift.html), but the analyzers are considered experimental. While this analyzer may be useful and provide valid results more testing must be completed to ensure that the false negative/false positive rates are acceptable.

In order to test with @MASTG-TOOL-0116 for dependencies with known vulnerabilities, we need to retrieve the corresponding file of the dependency manager used:

- For Carthage it is the file `Cartfile.resolved`.
- For CocoaPods it is the file `*.podspec` or `Podfile.lock`
- For SwiftPM it is the file `Package.swift` or `Package.resolved`

When scanning with @MASTG-TOOL-0116 it is sufficient to scan the file created by the dependency manager.

Before we can run the scan, you will need to obtain an API key for NVD, which is used to retrieve the latest CVE information. The API Key to access the NVD API can be requested from <https://nvd.nist.gov/developers/request-an-api-key>.

To start a scan for a project using SwiftPM, execute the following command:

```bash
$ dependency-check --enableExperimental -f SARIF --nvdApiKey <YOUR-API-KEY> -s Package.resolved
```

The output will be a SARIF file, which can be viewed in @MASTG-TOOL-0118 by using the Sarif Viewer Plugin. If any known vulnerabilities were identified, it will list them and their CVE number and description.

When scanning for CocoaPods or Carthage you can re-use the same command, but scanning the corresponding file of the dependency manager instead.
