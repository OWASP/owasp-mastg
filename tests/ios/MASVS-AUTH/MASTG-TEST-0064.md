---
masvs_v1_id:
- MSTG-AUTH-8
- MSTG-STORAGE-11
masvs_v2_id:
- MASVS-AUTH-2
platform: ios
title: Testing Biometric Authentication
masvs_v1_levels:
- L2
profiles: [L2]
status: deprecated
covered_by: [MASTG-TEST-0266, MASTG-TEST-0267, MASTG-TEST-0268, MASTG-TEST-0269, MASTG-TEST-0270, MASTG-TEST-0271]
deprecation_note: New version available in MASTG V2
---

## Overview

The usage of frameworks in an app can be detected by analyzing the app binary's list of shared dynamic libraries. This can be done by using @MASTG-TOOL-0060:

```bash
otool -L <AppName>.app/<AppName>
```

If `LocalAuthentication.framework` is used in an app, the output will contain both of the following lines (remember that `LocalAuthentication.framework` uses `Security.framework` under the hood):

```bash
/System/Library/Frameworks/LocalAuthentication.framework/LocalAuthentication
/System/Library/Frameworks/Security.framework/Security
```

If `Security.framework` is used, only the second one will be shown.

## Static Analysis

It is important to remember that the LocalAuthentication framework is an event-based procedure and as such, should not be the sole method of authentication. Though this type of authentication is effective on the user-interface level, it is easily bypassed through patching or instrumentation. Therefore, it is best to use the keychain service method, which means you should:

- Verify that sensitive processes, such as re-authenticating a user performing a payment transaction, are protected using the keychain services method.
- Verify that access control flags are set for the keychain item which ensure that the data of the keychain item can only be unlocked by means of authenticating the user. This can be done with one of the following flags:
    - `kSecAccessControlBiometryCurrentSet` (before iOS 11.3 `kSecAccessControlTouchIDCurrentSet`). This will make sure that a user needs to authenticate with biometrics (e.g. Face ID or Touch ID) before accessing the data in the keychain item. Whenever the user adds a fingerprint or facial representation to the device, it will automatically invalidate the entry in the Keychain. This makes sure that the keychain item can only ever be unlocked by users that were enrolled when the item was added to the keychain.
    - `kSecAccessControlBiometryAny` (before iOS 11.3 `kSecAccessControlTouchIDAny`). This will make sure that a user needs to authenticate with biometrics (e.g. Face ID or Touch ID) before accessing the data in the Keychain entry. The Keychain entry will survive any (re-)enroling of new fingerprints or facial representation. This can be very convenient if the user has a changing fingerprint. However, it also means that attackers, who are somehow able to enrole their fingerprints or facial representations to the device, can now access those entries as well.
    - `kSecAccessControlUserPresence` can be used as an alternative. This will allow the user to authenticate through a passcode if the biometric authentication no longer works. This is considered to be weaker than `kSecAccessControlBiometryAny` since it is much easier to steal someone's passcode entry by means of shouldersurfing, than it is to bypass the Touch ID or Face ID service.
- In order to make sure that biometrics can be used, verify that the `kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly` or the `kSecAttrAccessibleWhenPasscodeSet` protection class is set when the `SecAccessControlCreateWithFlags` method is called. Note that the `...ThisDeviceOnly` variant will make sure that the keychain item is not synchronized with other iOS devices.

> Note, a data protection class specifies the access methodology used to secure the data. Each class uses different policies to determine when the data
is accessible.

## Dynamic Analysis

[Objection Biometrics Bypass](https://github.com/sensepost/objection/wiki/Understanding-the-iOS-Biometrics-Bypass "Understanding the iOS Biometrics Bypass") can be used to bypass LocalAuthentication. Objection uses Frida to instrument the `evaluatePolicy` function so that it returns `True` even if authentication was not successfully performed. Use the `ios ui biometrics_bypass` command to bypass the insecure biometric authentication. Objection will register a job, which will replace the `evaluatePolicy` result. It will work in both, Swift and Objective-C implementations.

```bash
...itudehacks.DVIAswiftv2.develop on (iPhone: 13.2.3) [usb] # ios ui biometrics_bypass
(agent) Registering job 3mhtws9x47q. Type: ios-biometrics-disable
...itudehacks.DVIAswiftv2.develop on (iPhone: 13.2.3) [usb] # (agent) [3mhtws9x47q] Localized Reason for auth requirement: Please authenticate yourself
(agent) [3mhtws9x47q] OS authentication response: false
(agent) [3mhtws9x47q] Marking OS response as True instead
(agent) [3mhtws9x47q] Biometrics bypass hook complete
```

If vulnerable, the module will automatically bypass the login form.
