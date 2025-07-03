---
platform: android
title: Identifying Insecure Dependencies through SBOM Creation
id: MASTG-DEMO-0051
test: MASTG-TEST-0272
---

### Steps

Execute `cdxgen` in the root directory of the Android Studio project.

{{ run.sh }}

This will create a SBOM file that can be uploaded to @MASTG-TOOL-0132 by following @MASTG-TECH-0130.

### Observation

In the project of @MASTG-TOOL-0132, where the SBOM has been uploaded, the scan should have identified over 200 unique dependencies (components) with 7 vulnerable dependencies and 7 vulnerabilities (as more vulnerabilities might be found over time this number might increase).

{{ sbom.json }}

### Evaluation

Review each of the reported instances. The dependency `okhttp` has 2 known vulnerabilities and `okio` has 1 known vulnerability and they should all be updated to the latest version.

{{ output.json }}
