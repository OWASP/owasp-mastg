---
platform: android
title: Identifying Insecure Dependencies in Android Studio
id: MASTG-DEMO-0050
code: [java]
test: MASTG-TEST-0272
---

### Sample

{{ build.gradle.kts }}

### Steps

Execute `gradle` in Android Studio to trigger @MASTG-TOOL-0131.

{{ run.sh }}

### Observation

The scan has identified 303 unique dependencies with 4 vulnerable dependencies and 5 vulnerabilities (as more vulnerabilities might be found over time this number might increase). There are 57 vulnerabilities suppressed, if you have used the `suppress.xml` file.

{{ output.txt }}

### Evaluation

Due to the number of vulnerabilities, the `dependency-check` report can be lengthy and can contain false positives. Review each of the reported instances. The dependency `okhttp-4.9.1.jar` added in the `build.gradle.kts` has known vulnerabilities and should be updated to the latest version.
