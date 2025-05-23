---
platform: ios
title: Uses of kSecAccessControlBiometryCurrentSet with r2
id: MASTG-DEMO-0045
code: [swift]
test: MASTG-TEST-0270
---

### Sample

The following sample checks whether the app uses a biometric authentication API that detects the addition of a new biometric in the system settings after the application adds an entry to the keychain.

{{ MastgTest.swift }}

### Steps

1. Unzip the app package and locate the main binary file (@MASTG-TECH-0058), which in this case is `./Payload/MASTestApp.app/MASTestApp`.
2. Run `run.sh`.

{{ biometricAuthenticationFallback.r2 }}

{{ run.sh }}

### Observation

{{ output.asm }}

The output reveals the use of `SecAccessControlCreateWithFlags(allocator, protection, flags, error)` in the app. In this demo, we focus on the `flags` argument because it specifies the [Access Control](https://developer.apple.com/documentation/security/secaccesscontrol). `flags` is the third argument of the function, so it's at `x2/w2` register. By looking at the output, we can see that `w2` register holds value of `2`.

```assembly
mov w2, 2
bl sym.imp.SecAccessControlCreateWithFlags
```

The `flags` is an enum of [SecAccessControlCreateFlags](https://developer.apple.com/documentation/security/secaccesscontrolcreateflags). `2` corresponds to [kSecAccessControlBiometryAny](https://developer.apple.com/documentation/security/secaccesscontrolcreateflags/biometryany?language=objc). This means that the app invokes `SecAccessControlCreateWithFlags(..., kSecAccessControlBiometryAny)`, which means it will accept new biometric added in the system settings.

### Evaluation

The test fails because the output shows a reference to `SecAccessControlCreateWithFlags` with `kSecAccessControlBiometryAny`, which accepts any additional biometrics added after the Keychain entry was created. It's recommended to use the [`kSecAccessControlBiometryCurrentSet`](https://developer.apple.com/documentation/security/secaccesscontrolcreateflags/biometrycurrentset?language=objc) flag instead.
