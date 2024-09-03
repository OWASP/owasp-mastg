---
platform: ios
title: Uses of Weak Key Size in SecKeyCreateRandomKey with r2
code: [swift]
id: MASTG-DEMO-0011
test: MASTG-TEST-0206
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

In the output we can see how the `kSecAttrKeySizeInBits` attribute is set to `1024` bits (0x400 in hexadecimal) using the `x8` register. This is later used to call `SecKeyCreateRandomKey`.

{{ evaluation.txt }}

iOS doesn't guarantee that any file marked with `isExcludedFromBackupKey` will be excluded from a backup. Encrypt this file if necessary.
