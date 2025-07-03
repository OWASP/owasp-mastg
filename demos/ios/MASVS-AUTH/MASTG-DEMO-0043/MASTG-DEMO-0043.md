---
platform: ios
title: Uses of kSecAccessControlUserPresence with r2
id: MASTG-DEMO-0043
code: [swift]
test: MASTG-TEST-0268
---

### Sample

The following sample correctly uses the Keychain API for local authentication (`SecAccessControlCreateWithFlags`) but it uses the [`kSecAccessControlUserPresence`](https://developer.apple.com/documentation/security/secaccesscontrolcreateflags/userpresence) flag which allows fallback to device passcode when biometric authentication fails or isn't yet configured.

{{ MastgTest.swift }}

### Steps

1. Unzip the app package and locate the main binary file (@MASTG-TECH-0058), which in this case is `./Payload/MASTestApp.app/MASTestApp`.
2. Run `run.sh`.

{{ biometricAuthenticationFallback.r2 }}

{{ run.sh }}

### Observation

{{ output.asm }}

The output reveals the use of `SecAccessControlCreateWithFlags(allocator, protection, flags, error)` in the app. In this demo, we focus on the `flags` argument because it specifies the [Access Control](https://developer.apple.com/documentation/security/secaccesscontrol). `flags` is a third argument of the function, so it's at `x2/w2` register. By looking at the output, we can see that `w2` register holds value of `1`.

```assembly
mov w2, 1
bl sym.imp.SecAccessControlCreateWithFlags
```

The `flags` is an enum of [`SecAccessControlCreateFlags`](https://developer.apple.com/documentation/security/secaccesscontrolcreateflags). `1` corresponds with `kSecAccessControlUserPresence` (see [LAPublicDefines.h](https://github.com/xybp888/iOS-SDKs/blob/master/iPhoneOS18.4.sdk/System/Library/Frameworks/LocalAuthentication.framework/Headers/LAPublicDefines.h#L12-L18)). This means that the app invokes `SecAccessControlCreateWithFlags(..., kSecAccessControlUserPresence)`, which means it falls back to device's passcode authentication.

### Evaluation

The test fails because the output shows references to biometric verification that falls back to device's passcode authentication, specifically `kSecAccessControlUserPresence`.

Since this data requires protection with biometrics, it's recommended to use the [`kSecAccessControlBiometryCurrentSet`](https://developer.apple.com/documentation/security/secaccesscontrolcreateflags/biometrycurrentset) or [`kSecAccessControlBiometryAny`](https://developer.apple.com/documentation/security/secaccesscontrolcreateflags/biometryany) flags instead, being `kSecAccessControlBiometryCurrentSet` the most secure.
