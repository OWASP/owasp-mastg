---
platform: android
title: App Leaking Information about Unclosed SQL Cursor via StrictMode
id: MASTG-DEMO-0037
code: [kotlin]
test: MASTG-TEST-0263
---

### Sample

The snippet below shows sample code that enables a `StrictMode` policy to detect leaked (i.e., unclosed) SQLite objects. When such an object is detected, a log message is emitted to the system log.

The snippet then opens an SQL Cursor which remains unclosed, to trigger the policy.

{{ MastgTest.kt }}

### Steps

1. Install the app on your device.
2. Open the app and let it execute.
3. Execute `run.sh` which uses @MASTG-TECH-0009 to show the system logs created by `StrictMode`.

{{ run.sh }}

### Observation

The system log outputs all detected `StrictMode` policy violations.

{{ output.txt }}

### Evaluation

The test fails because `StrictMode` is enabled, as we can see from the system log output which shows that there is a location (`MastgTest.kt:35`) where an SQL cursor is not closed properly.

**Note:** The reported cursor not being closed is a different issue outside the scope of this demo.
