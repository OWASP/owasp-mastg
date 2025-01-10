---
platform: ios
title: Uses of isExcludedFromBackupKey with r2
code: [swift]
id: MASTG-DEMO-0019
test: MASTG-TEST-0215
---

### Sample

The code snippet below shows sample code that creates a file and marks it with `isExcludedFromBackupKey`.

{{ MastgTest.swift # function.asm # decompiled-o1-review.swift }}

### Steps

1. Unzip the app package and locate the main binary file (@MASTG-TECH-0058), which in this case is `./Payload/MASTestApp.app/MASTestApp`.
2. Run `run.sh`.

{{ isExcludedFromBackup.r2 }}

{{ run.sh }}

### Observation

The output reveals the use of `isExcludedFromBackupKey` in the app.

{{ output.asm }}

### Evaluation

The test fails because `secret.txt` might be restored from the backup and it contains sensitive data.

You can see the call to `isExcludedFromBackupKey` at `0x100004594` and the associated file, `secret.txt` at `0x10000443c`.

**Note**: Using artificial intelligence we're able to decompile the disassembled code and review it. The output is a human-readable version of the assembly code. The AI decompiled code may not perfect and might contain errors but, in this case, it clearly shows the use of `isExcludedFromBackupKey` and the associated file `secret.txt`.
