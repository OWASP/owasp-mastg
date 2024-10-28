---
platform: ios
title: Uses of isExcludedFromBackupKey to Exclude Data From Backups
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

The output reveals the use of `isExcludedFromBackupKey` in the app.

{{ output.txt }}

### Evaluation

The test fails because `secret.txt` might be restored from the backup and it contains sensitive data.

You can see the call to `isExcludedFromBackupKey` at `0x100004594` and the associated file, `secret.txt` at `0x10000443c`.
