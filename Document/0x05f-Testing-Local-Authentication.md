---
masvs_category: MASVS-AUTH
platform: android
---

# Android Local Authentication

## Overview

During local authentication, an app authenticates the user against credentials stored locally on the device. In other words, the user "unlocks" the app or some inner layer of functionality by providing a valid PIN, password or biometric characteristics such as face or fingerprint, which is verified by referencing local data. Generally, this is done so that users can more conveniently resume an existing session with a remote service or as a means of step-up authentication to protect some critical function.

As stated in chapter ["Mobile App Authentication Architectures"](0x04e-Testing-Authentication-and-Session-Management.md), authentication should always be enforced by a remote endpoint if possible. If local authentication is required, it should be linked to the system's KeyStore, since attackers can bypass local authentication if this is not the case.

There are two ways of implementing local authentication:

- **Event-based:** The application simply checks if the user can authenticate themselves, via either a biometric prompt or a device credentials prompt. After successful authentication, the application launches a specific functionality or shows additional data.
- **Result-based:** The application unlocks a cryptographic key which is protected by either biometrics or device credentials. The cryptographic key is securely stored in a HSM and cannot be used without the user (re)authenticating themselves. The unlocked key is then used to decrypt or sign sensitive data.

The first implementation, event-based, is inherently insecure for multiple reasons:

- Somewhere in the application there will be an if/else that distinguishes between a successful or a failed authentication attempt. By tampering with the application at runtime, it is possible to convince the application that the authentication attempt was successful.
- After a legitimate successful authentication, the application will either present sensitive information to the user, or it will allow the user to perform a specific action. This means that either some data is stored locally which is not properly protected, or some functionality is not properly protected and can be triggered even without proper user authentication.

The second implementation, result-based, is considered secure because:

- The unlocked key will be used to either decrypt sensitive information, or to unlock some sort of session token which can be used to trigger specific functionalities. Without unlocking the key, the data is not available and the functionality cannot be triggered.

Over the years, Android has introduced many different APIs for dealing with lockscreens, credentials, fingerprints and biometrics:

- KeyguardManager: Can authenticate the user, but only event-based. This is considered insecure.
- FingerprintManager: Deprecated in Android 9 (API level 28) in favor of BiometricPrompt.
- BiometricPrompt: Can authenticate the user, both event-based and result-based. This is considered secure if correctly implemented via result-based.
- BiometricManager: Can be used to verify if the device supports biometric authentication. This cannot be used to authenticate the user in any way.

### Biometric Authentication

The class [`BiometricManager`](https://developer.android.com/reference/kotlin/android/hardware/biometrics/BiometricManager "BiometricManager") can be used to verify if biometric hardware is available on the device and if it is configured by the user. This class does not offer any real security, as it only allows the application to check if biometric authentication is supported or not.

If biometric authentication is supported, the [`BiometricPrompt`](https://developer.android.com/reference/kotlin/android/hardware/biometrics/BiometricPrompt "BiometricPrompt") class can be used to show a system-provided biometric authentication dialog.

A detailed overview and explanation of the Biometric API on Android was published on the [Android Developer Blog](https://android-developers.googleblog.com/2019/10/one-biometric-api-over-all-android.html "One Biometric API Over all Android").

To correctly implement local authentication, the following steps need to be followed:

- The app creates a key in the KeyStore with `setUserAuthenticationRequired` and `setInvalidatedByBiometricEnrollment` set to true. Additionally, `setUserAuthenticationValidityDurationSeconds` should be set to -1.
- This key is used to encrypt information that is authenticating the user (e.g. session information or authentication token).
- A valid set of biometrics must be presented before the key is released from the KeyStore to decrypt the data, which is validated through the `authenticate` method and the `CryptoObject`.
- After successful authentication, the released `CryptoObject` is used to decrypt the previously encrypted information.
- This solution cannot be bypassed, even on rooted devices, as the key from the KeyStore can only be used after successful biometric authentication.

### Biometric Compatibility Library

Android provides a library called [Biometric](https://developer.android.com/jetpack/androidx/releases/biometric "Biometric library for Android") which offers a compatibility version of the `BiometricPrompt` and `BiometricManager` APIs, as implemented in Android 10, with full feature support back to Android 6.0 (API 23).

You can find a reference implementation and instructions on how to [show a biometric authentication dialog](https://developer.android.com/training/sign-in/biometric-auth "Show a biometric authentication dialog") in the Android developer documentation.

There are two `authenticate` methods available in the `BiometricPrompt` class. One of them expects a [`CryptoObject`](https://developer.android.com/reference/android/hardware/biometrics/BiometricPrompt.CryptoObject.html "CryptoObject"), which allows you to perform result-based biometric authentication.

### Biometric Authentication VS Device Credentials

When creating the key in the KeyStore, it is possible to specify which authentication methods are allowed to unlock the key. This can be done by calling `setUserAuthenticationType` which accepts the following arguments:

- KeyProperties.AUTH_BIOMETRIC_STRONG: Biometric only (face, fingerprint, iris)
- KeyProperties.AUTH_DEVICE_CREDENTIAL: Device credentials only (PIN, pattern, password)
- KeyProperties.AUTH_BIOMETRIC_STRONG | KeyProperties.AUTH_DEVICE_CREDENTIAL: Either biometric or device credential

Generally speaking, biometrics are more secure than device credentials as they cannot be copied from the legitimate user. Through shoulder-surfing, it is possible to obtain the device credentials from a user without their cooperation. On the other hand, in certain circumstances a PIN or password may offer more security, since a user can be physically forced to authenticate via biometrics.

### Remove Authentication Protected by Local Authentication

Local authentication is often added on top of an existing backend authentication flow (e.g. username + password). A common mistake is to encrypt the user's password with a biometrics-protected key so that local authentication can be used to unlock the password and authenticate to the backend.

This is undesirable and unnecessary. The user's password should only be known by them, and should not be stored anywhere on the device. A better approach is to obtain a device-specific authentication token and protect this with local authentication. This way it is not possible for an attacker to extract the password from the application and use it on different services.

### Invalidation Upon New Biometric Enrollment

Android 7.0 (API level 24) adds the `setInvalidatedByBiometricEnrollment(boolean invalidateKey)` method to `KeyGenParameterSpec.Builder`. When `invalidateKey` value is set to `true` (the default), keys that are valid for fingerprint authentication are irreversibly invalidated when a new fingerprint is enrolled. This prevents an attacker from retrieving the key even if they are able to enroll an additional fingerprint.

When a new fingerprint is enrolled, all previously protected keys are invalidated, which means the application needs to foresee a fallback authentication method to allow the user to enable biometric authentication again.
