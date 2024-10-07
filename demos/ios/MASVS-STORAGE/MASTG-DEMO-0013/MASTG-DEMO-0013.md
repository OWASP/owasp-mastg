---
platform: ios
title: Sensitive Data Not Excluded From Backup
code: [swift]
id: MASTG-DEMO-0013
test: MASTG-TEST-0210
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

iOS doesn't guarantee that any file marked with `isExcludedFromBackupKey` will be excluded from a backup. Encrypt this file if necessary.
