---
masvs_category: MASVS-AUTH
platform: android
title: Biometric Authentication
---

Biometric authentication is a convenient mechanism for authentication, but also introduces an additional attack surface when using it. The Android developer documentation gives an interesting [overview](https://source.android.com/docs/security/features/biometric) and indicators for [measuring biometric unlock security](https://source.android.com/docs/security/features/biometric/measure "Measuring Biometric Unlock Security").

The Android platform offers three different classes for biometric authentication:

- Android 10 (API level 29) and higher: `BiometricManager`
- Android 9 (API level 28) and higher: `BiometricPrompt`
- Android 6.0 (API level 23) and higher: `FingerprintManager` (deprecated in Android 9 (API level 28))

<img src="Images/Chapters/0x05f/biometricprompt-architecture.png" width="100%" />

The class [`BiometricManager`](https://developer.android.com/reference/kotlin/android/hardware/biometrics/BiometricManager "BiometricManager") can be used to verify if biometric hardware is available on the device and if it's configured by the user. If that's the case, the class [`BiometricPrompt`](https://developer.android.com/reference/kotlin/android/hardware/biometrics/BiometricPrompt "BiometricPrompt") can be used to show a system-provided biometric dialog.

The `BiometricPrompt` class is a significant improvement, as it allows to have a consistent UI for biometric authentication on Android and also supports more sensors than just fingerprint.

A very detailed overview and explanation of the Biometric API on Android was published on the [Android Developer Blog](https://android-developers.googleblog.com/2019/10/one-biometric-api-over-all-android.html "One Biometric API Over all Android").

[Show a biometric authentication dialog](https://developer.android.com/identity/sign-in/biometric-auth)

## Biometric Library

Android provides a library called [Biometric](https://developer.android.com/jetpack/androidx/releases/biometric "Biometric library for Android") (also see the [androidx.biometric API Reference](https://developer.android.com/reference/kotlin/androidx/biometric/package-summary)) which offers a compatibility version of the `BiometricPrompt` and `BiometricManager` APIs, as implemented in Android 10, with full feature support back to Android 6.0 (API 23).

You can find a reference implementation and instructions on how to [show a biometric authentication dialog](https://developer.android.com/training/sign-in/biometric-auth "Show a biometric authentication dialog") in the Android developer documentation.

There are two `authenticate` methods available in the `BiometricPrompt` class. One of them expects a [`CryptoObject`](https://developer.android.com/reference/android/hardware/biometrics/BiometricPrompt.CryptoObject.html "CryptoObject"), which adds an additional layer of security for the biometric authentication.

The authentication flow would be as follows when using CryptoObject:

- The app creates a key in the KeyStore with `setUserAuthenticationRequired` and `setInvalidatedByBiometricEnrollment` set to true. Additionally, `setUserAuthenticationValidityDurationSeconds` should be set to -1.
- This key is used to encrypt information that is authenticating the user (e.g. session information or authentication token).
- A valid set of biometrics must be presented before the key is released from the KeyStore to decrypt the data, which is validated through the `authenticate` method and the `CryptoObject`.
- This solution cannot be bypassed, even on rooted devices, as the key from the KeyStore can only be used after successful biometric authentication.

If `CryptoObject` is not used as part of the authenticate method, it can be bypassed by using Frida. See the "Dynamic Instrumentation" section for more details.

Developers can use several [validation classes](https://source.android.com/security/biometric#validation "Validation of Biometric Auth") offered by Android to test the implementation of biometric authentication in their app.

## Biometric Authentication for Protecting Sensitive Data or Operations

The confirm credential flow is available since Android 6.0 and is used to ensure that users do not have to enter app-specific passwords together with the lock screen protection. Instead: if a user has logged in to the device recently, then confirm-credentials can be used to unlock cryptographic materials from the `AndroidKeystore`. That is, if the user unlocked the device within the set time limits (`setUserAuthenticationValidityDurationSeconds`), otherwise the device needs to be unlocked again.

Note that the security of Confirm Credentials is only as strong as the protection set at the lock screen. This often means that simple predictive lock-screen patterns are used and therefore we do not recommend any apps which require L2 of security controls to use Confirm Credentials.

Reassure that the lock screen is set:

```java
KeyguardManager mKeyguardManager = (KeyguardManager) getSystemService(Context.KEYGUARD_SERVICE);
if (!mKeyguardManager.isKeyguardSecure()) {
    // Show a message that the user hasn't set up a lock screen.
}
```

- Create the key protected by the lock screen. In order to use this key, the user needs to have unlocked the device in the last X seconds, or the device needs to be unlocked again. Make sure that this timeout is not too long, as it becomes harder to ensure that it was the same user using the app as the user unlocking the device:

    ```java
    try {
        KeyStore keyStore = KeyStore.getInstance("AndroidKeyStore");
        keyStore.load(null);
        KeyGenerator keyGenerator = KeyGenerator.getInstance(
                KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore");

        // Set the alias of the entry in Android KeyStore where the key will appear
        // and the constrains (purposes) in the constructor of the Builder
        keyGenerator.init(new KeyGenParameterSpec.Builder(KEY_NAME,
                KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
                .setBlockModes(KeyProperties.BLOCK_MODE_CBC)
                .setUserAuthenticationRequired(true)
                        // Require that the user has unlocked in the last 30 seconds
                .setUserAuthenticationValidityDurationSeconds(30)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_PKCS7)
                .build());
        keyGenerator.generateKey();
    } catch (NoSuchAlgorithmException | NoSuchProviderException
            | InvalidAlgorithmParameterException | KeyStoreException
            | CertificateException | IOException e) {
        throw new RuntimeException("Failed to create a symmetric key", e);
    }
    ```

- Set up the lock screen to confirm:

    ```java
    private static final int REQUEST_CODE_CONFIRM_DEVICE_CREDENTIALS = 1; //used as a number to verify whether this is where the activity results from
    Intent intent = mKeyguardManager.createConfirmDeviceCredentialIntent(null, null);
    if (intent != null) {
        startActivityForResult(intent, REQUEST_CODE_CONFIRM_DEVICE_CREDENTIALS);
    }
    ```

- Use the key after lock screen:

    ```java
    @Override
    protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        if (requestCode == REQUEST_CODE_CONFIRM_DEVICE_CREDENTIALS) {
            // Challenge completed, proceed with using cipher
            if (resultCode == RESULT_OK) {
                //use the key for the actual authentication flow
            } else {
                // The user canceled or didn’t complete the lock screen
                // operation. Go to error/cancellation flow.
            }
        }
    }
    ```

## Invalidating Keys

Android 7.0 (API level 24) adds the `setInvalidatedByBiometricEnrollment(boolean invalidateKey)` method to `KeyGenParameterSpec.Builder`. When `invalidateKey` value is set to `true` (the default), keys that are valid for fingerprint authentication are irreversibly invalidated when a new fingerprint is enrolled. This prevents an attacker from retrieving they key even if they are able to enroll an additional fingerprint.

## Biometric Third-Party SDKs

Make sure that fingerprint authentication and/or other types of biometric authentication are exclusively based on the Android SDK and its APIs. If this is not the case, ensure that the alternative SDK has been properly vetted for any weaknesses. Make sure that the SDK is backed by the TEE/SE which unlocks a (cryptographic) secret based on the biometric authentication. This secret should not be unlocked by anything else, but a valid biometric entry. That way, it should never be the case that the fingerprint logic can be bypassed.
