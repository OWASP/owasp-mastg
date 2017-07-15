## Testing Local Authentication in Android Apps

During local authentication, an app authenticates the user against credentials stored locally on the device. In other words, the user "unlocks" the app or some inner layer of functionality by providing a valid PIN, password, or fingerprint, verified by referencing local data. Generally, this process is invoked for reasons such providing a user convenience for resuming an existing session with the remote service or as a means of step-up authentication to protect some critical function.

### Testing Biometric Authentication

#### Overview

Android Marshmallow (6.0) introduced public APIs for authenticating users via fingerprint. Access to the fingerprint hardware is provided through the [FingerprintManager class](https://developer.android.com/reference/android/hardware/fingerprint/). An app can request fingerprint authentication by instantiating a `FingerprintManager` object and calling its `authenticate()` method. The caller registers callback methods to handle possible outcomes of the authentication process (i.e. success, failure, or error). Note that this method lacks proof that performed biometric authentication has been performed – it is relatively easy to bypass using patching or instrumentation.

By using the fingerprint API in conjunction with the Android <code>KeyGenerator</code> class, apps may create a cryptographic key that must be "unlocked" with the user's fingerprint. This authentication feature is intended to furnish a more convenient form of user login. For example, to enable user access to a remote service, a symmetric key is created which encrypts the user PIN or authentication token. By calling <code>setUserAuthenticationRequired(true)</code> when creating the key, this ensures the user must re-authenticate to retrieve it. The encrypted authentication credentials can then be saved directly to regular storage on the the device (e.g. SharedPreferences). This design is a relatively safe way to be sure the user actually entered an authorized fingerprint.

#### Static Analysis

Begin by searching for `FingerprintManager.authenticate()` calls. The first parameter passed to this method should be a <code>CryptoObject</code> instance which is a [wrapper class for crypto objects](https://developer.android.com/reference/android/hardware/fingerprint/FingerprintManager.CryptoObject.html) supported by FingerprintManager. Should the parameter be set to `null`, this means the fingerprint authorization is purely event-bound, likely creating a security issue.

The creation of the key used to initialize the cipher wrapper can be traced back to the <code>CryptoObject</code>. Verify the key was both created using the <code>KeyGenerator</code> class in addition to <code>setUserAuthenticationRequired(true)</code> being called during creation of the <code>KeyGenParameterSpec</code> object (see code samples below).

Make sure to verify authentication logic. For the authentication to be successful, the remote endpoint **must** require the client to present the secret retrieved from the Keystore or an accepted value derived from this secret.

#### Dynamic Analysis

Patch the app or use runtime instrumentation to bypass fingerprint authentication on the client. For example, you could use Frida to call the `onAuthenticationSucceeded` callback method directly. Refer to the chapter "Tampering and Reverse Engineering on Android" for more information.

#### Remediation

Safely implementing fingerprint authentication requires following a few simple principles, starting by first checking if that type of authentication is even available. On the most basic front, the device must run Android 6.0 or higher (API 23+). Four other prerequisites must also be verified:

- Fingerprint hardware must be available:

```java
	 FingerprintManager fingerprintManager = (FingerprintManager)
                    context.getSystemService(Context.FINGERPRINT_SERVICE);
    fingerprintManager.isHardwareDetected();                
```

- The user must have a protected lockscreen:

```java
	 KeyguardManager keyguardManager = (KeyguardManager) context.getSystemService(Context.KEYGUARD_SERVICE);
	 keyguardManager.isKeyguardSecure();
```

- At least one finger should be registered:

```java
	fingerprintManager.hasEnrolledFingerprints();
```

- The application should have permission to ask for a user fingerprint:

```java
	context.checkSelfPermission(Manifest.permission.USE_FINGERPRINT) == PermissionResult.PERMISSION_GRANTED;
```

If any one of the above checks fail, the option for fingerprint authentication should not be offered.

Should all the above checks pass, fingerprint authentication may be implemented by creating a new AES key using the <code>KeyGenerator</code> class by adding <code>setUserAuthenticationRequired(true)</code> in <code>KeyGenParameterSpec.Builder</code>.

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

Note that in Android Nougat (7.0), it is possible to use `setInvalidatedByBiometricEnrollment(boolean)` as a method to implement fingerprint authentication. When the value is set to "true", an existing fingerprint will not be invalidated when new fingerprints are enrolled. Though this provides a degree of convenience for a user, it creates vulnerability by offering an opportunity where an attacker could add their fingerprint.

To perform encryption or decryption, create a <code>Cipher</code> object and initialize it with the AES key.

```java
	SecretKey keyspec = (SecretKey)keyStore.getKey(KEY_ALIAS, null);

    if (mode == Cipher.ENCRYPT_MODE) {
        cipher.init(mode, keyspec);
```

Keep in mind, a new key cannot be used immediately - it has to be authenticated through the `FingerprintManager` first. This involves wrapping the `Cipher` object into `FingerprintManager.CryptoObject` which is passed to `FingerprintManager.authenticate()` before it will be recognized.

```java
	cryptoObject = new FingerprintManager.CryptoObject(cipher);
	fingerprintManager.authenticate(cryptoObject, new CancellationSignal(), 0, this, null);
```

When authentication succeeds, the callback method `onAuthenticationSucceeded(FingerprintManager.AuthenticationResult result)` is called at which point, the authenticated `CryptoObject` can be retrieved from the result.

```java
public void authenticationSucceeded(FingerprintManager.AuthenticationResult result) {
	cipher = result.getCryptoObject().getCipher();

	(... do something with the authenticated cipher object ...)
}
```

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

For a more in-depth example, refer to this [article by Deivi Taka](https://www.sitepoint.com/securing-your-android-apps-with-the-fingerprint-api/#savingcredentials "Securing Your Android Apps with the Fingerprint API").

#### References

##### OWASP Mobile Top 10 2016

- M4 - Insecure Authentication - https://www.owasp.org/index.php/Mobile_Top_10_2016-M4-Insecure_Authentication

##### OWASP MASVS

- V4.7: "Biometric authentication, if any, is not event-bound (i.e. using an API that simply returns "true" or "false"). Instead, it is based on unlocking the keychain/keystore."

##### CWE

- CWE-287 - Improper Authentication
- CWE-604 - Use of Client-Side Authentication
