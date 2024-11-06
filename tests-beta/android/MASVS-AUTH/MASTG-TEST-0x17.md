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









### Third party SDKs

Make sure that fingerprint authentication and/or other types of biometric authentication are exclusively based on the Android SDK and its APIs. If this is not the case, ensure that the alternative SDK has been properly vetted for any weaknesses. Make sure that the SDK is backed by the TEE/SE which unlocks a (cryptographic) secret based on the biometric authentication. This secret should not be unlocked by anything else, but a valid biometric entry. That way, it should never be the case that the fingerprint logic can be bypassed.







### FingerprintManager

> This section describes how to implement biometric authentication by using the `FingerprintManager` class. Please keep in mind that this class is deprecated and the [Biometric library](https://developer.android.com/jetpack/androidx/releases/biometric "Biometric library for Android") should be used instead as a best practice. This section is just for reference, in case you come across such an implementation and need to analyze it.

Begin by searching for `FingerprintManager.authenticate` calls. The first parameter passed to this method should be a `CryptoObject` instance which is a [wrapper class for crypto objects](https://developer.android.com/reference/android/hardware/fingerprint/FingerprintManager.CryptoObject.html "FingerprintManager.CryptoObject") supported by FingerprintManager. Should the parameter be set to `null`, this means the fingerprint authorization is purely event-based, likely creating a security issue.

The creation of the key used to initialize the cipher wrapper can be traced back to the `CryptoObject`. Verify the key was both created using the `KeyGenerator` class in addition to `setUserAuthenticationRequired(true)` being called during creation of the `KeyGenParameterSpec` object (see code samples below).

Make sure to verify the authentication logic. For the authentication to be successful, the remote endpoint **must** require the client to present the secret retrieved from the KeyStore, a value derived from the secret, or a value signed with the client private key (see above).

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

It is important to remember that not every Android device offers hardware-backed key storage. The `KeyInfo` class can be used to find out whether the key resides inside secure hardware such as a Trusted Execution Environment (TEE) or Secure Element (SE).

```java
SecretKeyFactory factory = SecretKeyFactory.getInstance(getEncryptionKey().getAlgorithm(), ANDROID_KEYSTORE);
KeyInfo secetkeyInfo = (KeyInfo) factory.getKeySpec(yourencryptionkeyhere, KeyInfo.class);
secetkeyInfo.isInsideSecureHardware()
```

On certain systems, it is possible to enforce the policy for biometric authentication through hardware as well. This is checked by:

```java
keyInfo.isUserAuthenticationRequirementEnforcedBySecureHardware();
```

The following describes how to do fingerprint authentication using a symmetric key pair.

Fingerprint authentication may be implemented by creating a new AES key using the `KeyGenerator` class by adding `setUserAuthenticationRequired(true)` in `KeyGenParameterSpec.Builder`.

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

The following describes how to do fingerprint authentication using an asymmetric key pair.

To implement fingerprint authentication using asymmetric cryptography, first create a signing key using the `KeyPairGenerator` class, and enroll the public key with the server. You can then authenticate pieces of data by signing them on the client and verifying the signature on the server. A detailed example for authenticating to remote servers using the fingerprint API can be found in the [Android Developers Blog](https://android-developers.googleblog.com/2015/10/new-in-android-samples-authenticating.html "Authenticating to remote servers using the Fingerprint API").

A key pair is generated as follows:

```java
KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore");
keyPairGenerator.initialize(
        new KeyGenParameterSpec.Builder(MY_KEY,
                KeyProperties.PURPOSE_SIGN)
                .setDigests(KeyProperties.DIGEST_SHA256)
                .setAlgorithmParameterSpec(new ECGenParameterSpec("secp256r1"))
                .setUserAuthenticationRequired(true)
                .build());
keyPairGenerator.generateKeyPair();
```

To use the key for signing, you need to instantiate a CryptoObject and authenticate it through `FingerprintManager`.

```java
Signature.getInstance("SHA256withECDSA");
KeyStore keyStore = KeyStore.getInstance("AndroidKeyStore");
keyStore.load(null);
PrivateKey key = (PrivateKey) keyStore.getKey(MY_KEY, null);
signature.initSign(key);
CryptoObject cryptoObject = new FingerprintManager.CryptoObject(signature);

CancellationSignal cancellationSignal = new CancellationSignal();
FingerprintManager fingerprintManager =
        context.getSystemService(FingerprintManager.class);
fingerprintManager.authenticate(cryptoObject, cancellationSignal, 0, this, null);
```

You can now sign the contents of a byte array `inputBytes` as follows.

```java
Signature signature = cryptoObject.getSignature();
signature.update(inputBytes);
byte[] signed = signature.sign();
```

- Note that in cases where transactions are signed, a random nonce should be generated and added to the signed data. Otherwise, an attacker could replay the transaction.
- To implement authentication using symmetric fingerprint authentication, use a challenge-response protocol.







- Check for setInvalidatedByBiometricEnrollment






If `CryptoObject` is not used as part of the authenticate method, it can be bypassed by using Frida. See the "Dynamic Instrumentation" section for more details.





### Implementing biometric authentication

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

