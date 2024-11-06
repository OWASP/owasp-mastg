---
platform: android
title: Insecure Local Authentication
id: MASTG-TEST-0x017
type: [dynamic]
available_since: 21
weakness: MASWE-0044
---

## Overview

Applications can implement local authentication in various ways, as explained in ["Android Local Authentication"](../../../Document/0x05f-Testing-Local-Authentication.md#Android%20Local%20Authentication). To make sure the application uses local authentication correctly, you need to verify if the application uses result-based authentication.

If the application uses event-based authentication instead of result-based authentication, the authentication flow can be bypassed by tools such as @MASTG-TOOL-0001 or @MASTG-TOOL-0029.

## Steps

1. Onboard the application and enable local authentication. This is an application-specific feature that may or may not be available. If no local authentication is available, the test is not applicable.
2. Launch the application with @MASTG-TOOL-0038 and use the [fingerprint-bypass.js script](https://github.com/WithSecureLABS/android-keystore-audit/blob/master/frida-scripts/fingerprint-bypass.js) and [fingerprint-bypass-via-exception-handling.js](https://github.com/WithSecureLabs/android-keystore-audit/blob/master/frida-scripts/fingerprint-bypass-via-exception-handling.js) scripts. In the first case, the flow should continue automatically, while in the second case, you have to run the bypass() function once the device credentials or biometrics are requested.

## Observation

The application may respond in different ways:

- The application may crash, due to the crypto object not being available.
- The application may continue with the authentication flow and authenticate the user.
- The application doesn't respond in any way and the biometrics or device credential screen remains open.

## Evaluation

The test case fails if you were able to authenticate to the application without providing your biometrics or device credentials. If the application did not respond differently due to the scripts, a custom hook can potentially still be used to bypass the local authentication flow and the results are inconclusive.

## Mitigation

Ensure that the app uses the unlocked key to decrypt local storage after the user has authenticated.

### Implementing biometric authentication

Make sure that the user has configured local authentication:

```java
KeyguardManager mKeyguardManager = (KeyguardManager) getSystemService(Context.KEYGUARD_SERVICE);
if (!mKeyguardManager.isKeyguardSecure()) {
    // Show a message that the user hasn't set up a lock screen.
}
```

- Create the key protected by local authentication. In order to use this key, the user needs to have unlocked the device in the last X seconds, or the device needs to be unlocked again.

    ```java

    try {
        KeyGenerator keyGenerator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore");
        keyGenerator.init(new KeyGenParameterSpec.Builder(
                "myLocalAuthenticationKey",
                KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT) 
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setUserAuthenticationRequired(true) 
                 // Require that the user has unlocked in the last 30 seconds
                .setUserAuthenticationValidityDurationSeconds(30)
                .build());
        SecretKey key = keyGenerator.generateKey(); 
    } catch (Exception e) {
        throw new RuntimeException("Failed to generate key", e);
    }
    ```

- Obtain a reference to a `Cipher` for the generated key:

    ```java
    KeyStore keyStore = KeyStore.getInstance("AndroidKeyStore");
    keyStore.load(null); 

    SecretKey key = (SecretKey) keyStore.getKey("myLocalAuthenticationKey", null); 

    Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
    cipher.init(Cipher.DECRYPT_MODE , key); 
    ```

- Create a new BiometricPrompt.CryptoObject from the generated cipher.

    ```java
    BiometricPrompt.CryptoObject cryptoObject = null;
    try {
        cryptoObject = new BiometricPrompt.CryptoObject(cipher);
    } catch (Exception e) {
        e.printStackTrace();
    }
    ```

- Trigger a BiometricPrompt to unlock the key:

    ```java
    BiometricPrompt.AuthenticationCallback authenticationCallback = new BiometricPrompt.AuthenticationCallback() {
        @Override
        public void onAuthenticationSucceeded(BiometricPrompt.AuthenticationResult result) {
            Toast.makeText(context, "Authentication Succeeded", Toast.LENGTH_SHORT).show();

            if (result.getCryptoObject() != null) {
                // Perform secure operation with the CryptoObject (e.g., decryption)
                try {
                    Cipher cipher = result.getCryptoObject().getCipher();
                    // Use  unlocked cipher
                    byte[] decryptedData = cipher.doFinal(encryptedData);
                } catch (Exception e) {
                    e.printStackTrace();
                }
            }
        }

        @Override
        public void onAuthenticationFailed() {
            Toast.makeText(context, "Authentication Failed", Toast.LENGTH_SHORT).show();
        }

        @Override
        public void onAuthenticationError(int errorCode, CharSequence errString) {
            Toast.makeText(context, "Authentication Error: " + errString, Toast.LENGTH_SHORT).show();
        }
    };

    // Configure the prompt
    BiometricPrompt.PromptInfo promptInfo = new BiometricPrompt.PromptInfo.Builder()
            .setTitle("Authenticate")
            .setSubtitle("Confirm your identity to proceed")
            .setAllowedAuthenticators(BiometricManager.Authenticators.BIOMETRIC_STRONG | BiometricManager.Authenticators.DEVICE_CREDENTIAL)
            .build();

    // Launch the prompt
    BiometricPrompt biometricPrompt = new BiometricPrompt((FragmentActivity) context,
            Executors.newSingleThreadExecutor(), authenticationCallback);

    biometricPrompt.authenticate(promptInfo, cryptoObject);
    ```

### FingerprintManager

> This section describes how to implement biometric authentication by using the `FingerprintManager` class. Please keep in mind that this class is deprecated and the [Biometric library](https://developer.android.com/jetpack/androidx/releases/biometric "Biometric library for Android") should be used instead as a best practice. This section is just for reference, in case you come across such an implementation and need to analyze it.

The creation of the key used to initialize the cipher wrapper can be traced back to the `CryptoObject`. Verify the key was both created using the `KeyGenerator` class in addition to `setUserAuthenticationRequired(true)` being called during creation of the `KeyGenParameterSpec` object (see code samples below).

Safely implementing fingerprint authentication requires following a few simple principles, starting by first checking if that type of authentication is even available. On the most basic front, the device must run Android 6.0 or higher (API 23+). Four other prerequisites must also be verified:

- The permission must be requested in the Android Manifest:

    ```xml
    <uses-permission
        android:name="android.permission.USE_FINGERPRINT" />
    ```

- Fingerprint hardware must be available:

    ```java
    FingerprintManager fingerprintManager = (FingerprintManager)
                    context.getSystemService(Context.FINGERPRINT_SERVICE);
    fingerprintManager.isHardwareDetected();
    ```

- The user must have a protected lock screen:

    ```java
    KeyguardManager keyguardManager = (KeyguardManager) context.getSystemService(Context.KEYGUARD_SERVICE);
    keyguardManager.isKeyguardSecure();  //note if this is not the case: ask the user to setup a protected lock screen
    ```

- At least one finger should be registered:

    ```java
    fingerprintManager.hasEnrolledFingerprints();
    ```

- The application should have permission to ask for a user fingerprint:

    ```java
    context.checkSelfPermission(Manifest.permission.USE_FINGERPRINT) == PermissionResult.PERMISSION_GRANTED;
    ```

If any of the above checks fail, the option for fingerprint authentication should not be offered.

Not every Android device offers hardware-backed key storage. The `KeyInfo` class can be used to find out whether the key resides inside secure hardware such as a Trusted Execution Environment (TEE) or Secure Element (SE).

```java
SecretKeyFactory factory = SecretKeyFactory.getInstance(getEncryptionKey().getAlgorithm(), ANDROID_KEYSTORE);
KeyInfo secetkeyInfo = (KeyInfo) factory.getKeySpec(yourencryptionkeyhere, KeyInfo.class);
secetkeyInfo.isInsideSecureHardware()
```

On certain systems, it is possible to enforce the policy for biometric authentication through hardware as well. This is checked by:

```java
keyInfo.isUserAuthenticationRequirementEnforcedBySecureHardware();
```

If all requirements are met, the actual key can be created via the `KeyGenerator` class by adding `setUserAuthenticationRequired(true)` in `KeyGenParameterSpec.Builder`:

```java
generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, KEYSTORE);

generator.init(new KeyGenParameterSpec.Builder (KEY_ALIAS,
        KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
        .setBlockModes(KeyProperties.BLOCK_MODE_CBC)
        .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_PKCS7)
        .setUserAuthenticationRequired(true)
        .build()
);

generator.generateKey();
```

To perform encryption or decryption with the protected key, create a `Cipher` object and initialize it with the key alias.

```java
SecretKey keyspec = (SecretKey)keyStore.getKey(KEY_ALIAS, null);

if (mode == Cipher.ENCRYPT_MODE) {
    cipher.init(mode, keyspec);
```

Keep in mind, a new key cannot be used immediately - it has to be authenticated through the `FingerprintManager` first. This involves wrapping the `Cipher` object into `FingerprintManager.CryptoObject` which is passed to `FingerprintManager.authenticate` before it will be recognized.

```java
cryptoObject = new FingerprintManager.CryptoObject(cipher);
fingerprintManager.authenticate(cryptoObject, new CancellationSignal(), 0, this, null);
```

The callback method `onAuthenticationSucceeded(FingerprintManager.AuthenticationResult result)` is called when the authentication succeeds. The authenticated `CryptoObject` can then be retrieved from the result.

```java
public void authenticationSucceeded(FingerprintManager.AuthenticationResult result) {
    cipher = result.getCryptoObject().getCipher();

    //(... do something with the authenticated cipher object ...)
}
```
