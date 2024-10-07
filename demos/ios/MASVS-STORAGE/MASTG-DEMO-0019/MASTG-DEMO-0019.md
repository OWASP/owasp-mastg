---
platform: ios
title: Sensitive Data Not Excluded From Backup
code: [swift]
id: MASTG-DEMO-0019
test: MASTG-TEST-0215
---

### Sample

The code snippet below shows sample code that creates a file and marks it with `isExcludedFromBackupKey`.

{{ MastgTest.swift }}

### Steps

1. Unzip the app package and locate the main binary file (@MASTG-TECH-0058), which in this case is `./Payload/MASTestApp.app/MASTestApp`.
2. Run `run.sh`.

{{ run.sh }}

### Observation

The output contains information that `isExcludedFromBackupKey` was used in the app.

{{ output.txt }}

### Evaluation

The test fails because `secret.txt` might be restored from the backup and it contains sensitive data.
