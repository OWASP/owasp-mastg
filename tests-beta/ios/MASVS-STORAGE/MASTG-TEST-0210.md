---
platform: ios
title: Sensitive Data Not Excluded From Backup
id: MASTG-TEST-0210
type: [static, filesystem]
weakness: MASWE-0004
---

## Overview

iOS provides the [`isExcludedFromBackup`](https://developer.apple.com/documentation/foundation/urlresourcevalues/1780002-isexcludedfrombackup) API to guide the system not to back up a given file. However, this API [does not guarantee that a file will be excluded](https://developer.apple.com/documentation/foundation/optimizing_your_app_s_data_for_icloud_backup/#3928527):

> "The `isExcludedFromBackup` resource value exists only to provide guidance to the system about which files and directories it can exclude; it’s not a mechanism to guarantee those items never appear in a backup or on a restored device."

Therefore, the only way to properly protect your files from a backup is to encrypt them.

## Steps

1. Run a static analysis tool such as @MASTG-TOOL-0073 on the app binary, or use a dynamic analysis tool like @MASTG-TOOL-0039, and look for uses of `isExcludedFromBackup` API.

## Observation

Inspect all files that you marked with `isExcludedFromBackup`.

## Evaluation

Make sure to encrypt any files you want to protect from a backup, as `isExcludedFromBackup` does not guarantee that a file will be excluded.
