---
platform: android
title: Identifying Insecure Dependencies in Android Studio
id: MASTG-DEMO-0021
code: [java]
test: MASTG-TEST-0216
---

### Sample

{{ build.gradle.kts # build.gradle.kts }}

### Steps

Execute `gradle` in Android Studio to trigger @MASTG-TOOL-0116.

{{ run.sh }}

### Observation

The scan has identified 262 unique dependencies with 35 vulnerable dependencies and 83 vulnerabilities (as more vulnerabilities might be found over time this number might increase).

{{ output.txt }}

### Evaluation

Due to the number of vulnerabilities, the `dependency-check` report can be lengthy and can contain false positives. Review each of the reported instances. The dependency `okhttp-4.8.0.jar` added in the `build.gradle.kts` has known vulnerabilities and should be updated to the latest version.
