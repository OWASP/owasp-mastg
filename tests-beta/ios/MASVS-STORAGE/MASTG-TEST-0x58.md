---
platform: ios
title: Runtime Use of the Keychain API to Exclude Data from Backups and Prevent Access on Other Devices
id: MASTG-TEST-0x58
type: [dynamic]
weakness: MASWE-0004
---

## Overview

This test verifies whether your app correctly use the Keychain API to exclude sensitive data from backups, so it won't be transferred to another devices.

An app can restrict the data access to the current device with [kSecAttrAccessibleWhenUnlockedThisDeviceOnly](https://developer.apple.com/documentation/security/ksecattraccessiblewhenunlockedthisdeviceonly) or [kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly](https://developer.apple.com/documentation/security/ksecattraccessiblewhenpasscodesetthisdeviceonly) flag. However, if you back up and restore on the same device, this data will also be restored. Therefore, it only prevents the data from being transferred to another device. Apple discourages storing large amounts of data in the Keychain, so it’s best to store only an encryption key there and keep the rest of the files in the filesystem.

## Steps

1. Use runtime method hooking (see @MASTG-TECH-0095) and look for uses of [`SecAccessControlCreateWithFlags`](https://developer.apple.com/documentation/security/secaccesscontrolcreatewithflags(_:_:_:_:)) and specific flags.

2. Exercise the app to trigger the creation of entries in the keychain. 

## Observation

The output should contain a list of locations where the `SecAccessControlCreateWithFlags` function is called including all used flags.

## Evaluation

The test case fails if the items in the Keychain don't satisfy your app's security requirements. For example, your app might store sensitive data that you want to keep accessible only on this device. Then, such an item in the Keychain should use `kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly` or `kSecAttrAccessibleWhenUnlockedThisDeviceOnly`.
