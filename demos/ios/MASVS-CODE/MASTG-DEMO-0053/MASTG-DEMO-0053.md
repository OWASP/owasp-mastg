---
platform: ios
title: Identifying Insecure Dependencies in SwiftPM through SBOM creation
id: MASTG-DEMO-0053
test: MASTG-TEST-0273
---

### Steps

Execute @MASTG-TOOL-0134 in the root directory of the Xcode project.

{{ run.sh }}

This will create a SBOM file that can be uploaded to @MASTG-TOOL-0132 by following @MASTG-TECH-0132.

### Observation

In the project of @MASTG-TOOL-0132, where the SBOM has been uploaded, the scan should have identified 2 unique dependencies (components) with 2 vulnerable dependencies and 2 vulnerabilities (as more vulnerabilities might be found over time this number might increase).

{{ output.txt }}

### Evaluation

Review each of the reported instances. The dependency `swift-nio` has 2 known vulnerabilities and should be updated to the latest version.
