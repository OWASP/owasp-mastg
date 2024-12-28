---
platform: ios
title: Data In Keychain Not Excluded From Backup On Another Device
id: MASTG-TEST-0x58
type: [dynamic]
weakness: MASWE-0004
---

## Overview

This test verifies whether your app correctly use the Keychain to exclude sensitive data from backups.

An app can restrict the data access to the current device with [kSecAttrAccessibleWhenUnlockedThisDeviceOnly](https://developer.apple.com/documentation/security/ksecattraccessiblewhenunlockedthisdeviceonly) flag. However, if you back up and restore on the same device, this data will also be restored. Therefore, it only prevents the data from being transferred to another device. Apple discourages storing large amounts of data in the Keychain, so it’s best to store only an encryption key there and keep the rest of the files in the filesystem.

## Steps

1. Use [iTunes or Finder](https://support.apple.com/en-us/120001) to back up the iPhone and restore it on another device.
2. Review data in Keychain with @MASTG-TECH-0061

## Observation

The output should contain a list of items in the Keychain.

## Evaluation

The test case fails if you find data you intended to restrict to the current device only, but it’s accessible on another device.
