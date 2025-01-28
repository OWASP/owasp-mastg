---
platform: ios
title: Sensitive Data Not Excluded From Backup
id: MASTG-TEST-0215
type: [static]
weakness: MASWE-0004
---

## Overview

This test verifies whether your app uses `isExcludedFromBackup` API to instructs the system to exclude sensitive files from backups. This API [does not guarantee guarantee the actual exclusion](https://developer.apple.com/documentation/foundation/optimizing_your_app_s_data_for_icloud_backup/#3928527). According to the documentation:

> "The `isExcludedFromBackup` resource value exists only to provide guidance to the system about which files and directories it can exclude; it's not a mechanism to guarantee those items never appear in a backup or on a restored device."

In this test, we identify all locations where you use the `isExcludedFromBackup` API to expose files that might end up in the backup, even though you don’t want them to.

## Steps

1. Run a static analysis tool such as @MASTG-TOOL-0073 on the app binary, or use a dynamic analysis tool like @MASTG-TOOL-0039, and look for uses of `isExcludedFromBackup` API.

## Observation

The output should contain the disassembled code of the functions using `isExcludedFromBackup` and if possible the list of affected files.

## Evaluation

The test case fails if you can find the use of `isExcludedFromBackup` within the source code and if any of the affected files can be considered sensitive.

For the sensitive files found, and in addition to using `isExcludedFromBackup`, make sure to encrypt them, as `isExcludedFromBackup` does not guarantee the exclusion.
