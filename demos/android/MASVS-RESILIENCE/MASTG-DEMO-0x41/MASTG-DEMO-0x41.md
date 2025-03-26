---
platform: android
title: App Leaking Information about Unclosed SQL Cursor via StrictMode
id: MASTG-DEMO-0x41
code: [kotlin]
test: MASTG-TEST-0x41
---

### Sample

The snippet below shows sample code that enables a `StrictMode` policy to detect leaked (i.e., unclosed) SQLite objects. When such an object is detected, a log message is emitted to the system log.

The snippet then opens an SQL Cursor which remains unclosed, to trigger the policy.

{{ MastgTest.kt }}

### Steps

1. Install the app on your device.
2. Execute `run.sh` which uses @MASTG-TECH-0009 to show the system logs created by `StrictMode`.
3. Open the app and let it execute.

{{ run.sh }}

### Observation

The system log outputs all detected `StrictMode` policy violations.

{{ output.txt }}

### Evaluation

The system log output revealed one location where a SQL Cursor is not properly closed. We can therefore conclude that the test fails because `StrictMode` is enabled.
