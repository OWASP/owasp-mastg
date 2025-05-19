---
platform: ios
title: Scanning Package Manager Artifacts for Insecure iOS Dependencies
id: MASTG-DEMO-0052
code: [java]
test: MASTG-TEST-0273
---

### Sample

{{ Package.resolved # Package.resolved }}

### Steps

Let's run @MASTG-TOOL-0131 in the root directory of the Xcode project.

{{ run.sh }}

### Observation

The SARIF file can be opened by using @MASTG-TOOL-0133 for analyzing the identified vulnerabilities.

{{ output.txt }}

### Evaluation

Review each of the reported instances, as it can contain false positives. The library `swift-nio` has at least 2 known vulnerabilities as part of Swift with CVE-2022-3918 and CVE-2022-1642 and should be updated to the latest version.
