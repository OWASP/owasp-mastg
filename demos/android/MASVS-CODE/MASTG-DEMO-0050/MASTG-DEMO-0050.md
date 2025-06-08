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

The scan identified 303 unique dependencies, four of which are vulnerable, as well as five vulnerabilities. More vulnerabilities may be found over time, so this number may increase. If you have used the `suppress.xml` file, there are 57 suppressed vulnerabilities.

{{ output.txt }}

### Evaluation

Due to the number of vulnerabilities, the `dependency-check` report can be lengthy and can contain false positives. Review each of the reported instances. The dependency `okhttp-4.9.1.jar` added in the `build.gradle.kts` has known vulnerabilities and should be updated to the latest version.
