---
platform: ios
title: Secure Policy Of Data In Private Storage
id: MASTG-TEST-0x52-3
type: [static, dynamic]
weakness: MASWE-0008
---

## Overview

This test verifies whether the data is stored with secure policy inside the Keychain. Apple provides many policies that can enforce the user to:

- authenticate with biometrics to access data ([kSecAccessControlBiometryAny](https://developer.apple.com/documentation/security/secaccesscontrolcreateflags/biometryany))
- set up a password on the device to store data ([kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly](https://developer.apple.com/documentation/security/ksecattraccessiblewhenpasscodesetthisdeviceonly))
- access this data only on the current device ([kSecAttrAccessibleWhenUnlockedThisDeviceOnly](https://developer.apple.com/documentation/security/ksecattraccessiblewhenunlockedthisdeviceonly))
- and [more](https://developer.apple.com/documentation/security/item-attribute-keys-and-values#Accessibility-Values)

## Steps

1. Run a static analysis (e.g. @MASTG-TOOL-0073) on the app binary, or use @MASTG-TOOL-0038 to dynamically verify the properties of the keychain items during the app runtime.

2. (Static analysis only) Search for APIs that indicates a use of Keychain. This API includes:
    - SecItemAdd
    - SecAccessControlCreateWithFlags

3. Verify whether the APIs above make use of security policies mentioned in the Overview or [Apple's documentation](https://developer.apple.com/documentation/security/item-attribute-keys-and-values#Accessibility-Values)

## Observations

The output should allow you to identify security policies assigned to items in the keychain.

## Evaluation

The test case fails if the items in the Keychain don't satisfy your app's security requirements. For example, your app might store sensitive data that you want to keep accessible only on this device. Then, such an item in the Keychain should use `kSecAttrAccessibleWhenUnlockedThisDeviceOnly`.
