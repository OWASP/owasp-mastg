## Testing Local Authentication in Android Apps

During local authentication, an app authenticates by referencing user input against credentials stored locally on the device. In other words, the user "unlocks" the app or some inner layer of functionality by providing a valid PIN, password, or fingerprint, verified by referencing local data. Generally, this process is invoked for reasons such providing a user convenience for resuming an existing session with the remote service or as a means of step-up authentication to protect some critical function.

### Testing Biometric Authentication

#### Overview

Android Marshmallow (6.0) introduced public APIs for authenticating users via fingerprint. Access to the fingerprint hardware is provided through the [FingerprintManager class](https://developer.android.com/reference/android/hardware/fingerprint/). An app can request fingerprint authentication by instantiating a ‘FingerprintManager’ object and calling its <code>authenticate(0)</code> method. The caller registers callback methods to handle possible outcomes of the authentication process (i.e. success, failure, or error).

By using the fingerprint API in conjunction with the Android <code>KeyGenerator</code> class, apps may create a cryptographic key that must be "unlocked" with a user fingerprint. This authentication feature is intended to furnish a more convenient form of user login. For example, to enable user access for a remote service, a symmetric key is created which encrypts the user PIN or authentication token. By calling <code>setUserAuthenticationRequired(true)</code> when creating the key, this ensures the user must re-authenticate using a fingerprint. The encrypted authentication data itself is saved directly to regular storage on the the device (e.g. SharedPreferences).

Though the design is relatively safe, such an assumption could lead to implementation of insecure fingerprint authentication. For instance, a developer could conclude successful authentication is based solely on retrieval of the <code>onAuthenticationSucceeded</code> callback. However, this lacks concrete proof a user performed biometric authentication – it is relatively easy to patch or bypass the method using instrumentation. Leveraging the Keystore is the only way to be reasonably sure a user actually entered an authorized fingerprint.

#### Static Analysis

Begin by searching for <code>FingerprintManager.authenticate()</code> calls. The first parameter passed to this method should be a <code>CryptoObject</code> instance which is a [wrapper class for crypto objects](https://developer.android.com/reference/android/hardware/fingerprint/FingerprintManager.CryptoObject.html) supported by FingerprintManager. Should the parameter be set to <code>null</code>, this means the fingerprint authorization is purely event-bound, likely creating a security issue.

The creation of the key used to initialize the cipher wrapper can be traced back to the <code>CryptoObject</code>. Verify the key was both created using the <code>KeyGenerator</code> class in addition to <code>setUserAuthenticationRequired(true)</code> being called during creation of the <code>KeyGenParameterSpec</code> object (see code samples below).

Make sure to verify authentication logic. For the authentication to be successful, the remote endpoint **must** require the client to present the secret retrieved from the Keystore or an accepted value derived from this secret.

#### Dynamic Analysis

Patch the app or use runtime instrumentation to bypass fingerprint authentication on the client. For example, you could use Frida to call on the <code>onAuthenticationSucceeded</code> and directly inject the callback to circumvent fingerprint authentication. Refer to the chapter "Tampering and Reverse Engineering on Android" for more information.

#### Remediation

Safely implementing fingerprint authentication requires following a few simple principals, starting by first checking it is actually possible. On the most basic front, the device must run Android 6.0 or higher (SDK 23+). Four other prerequisites must also be verified:

- The user must have a protected lockscreen:

```java
	 KeyguardManager keyguardManager = (KeyguardManager) context.getSystemService(Context.KEYGUARD_SERVICE);
	 keyguardManager.isKeyguardSecure();
```
- Fingerprint hardware must be available:

```java
	 FingerprintManager fingerprintManager = (FingerprintManager)
                    context.getSystemService(Context.FINGERPRINT_SERVICE);
    fingerprintManager.isHardwareDetected();                
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

Note that in Android Nougat (7.0), it is possible to use <code>setInvalidatedByBiometricEnrollment(boolean)</code> as a method to implement fingerprint authentication. When the value is set to “true,” an existing fingerprint will not be invalidated when new fingerprints are enrolled. Though this provides a degree of convenience for a user, it creates vulnerability by offering an opportunity where an attacker could add their fingerprint.

To perform encryption or decryption, create a <code>Cipher</code> object and initialize it with the AES key.

```java
	SecretKey keyspec = (SecretKey)keyStore.getKey(KEY_ALIAS, null);

    if (mode == Cipher.ENCRYPT_MODE) {
        cipher.init(mode, keyspec);
```

Keep in mind, a new key cannot be used immediately - it has to be authenticated through the <code>FingerprintManager</code> first. This involves wrapping the <code>Cipher</code> object into <code>FingerprintManager.CryptoObject</code> which is passed to <code>FingerprintManager.authenticate()</code> before it will be recognized.

```java
	cryptoObject = new FingerprintManager.CryptoObject(cipher);
	fingerprintManager.authenticate(cryptoObject, new CancellationSignal(), 0, this, null);
```

When authentication succeeds, the callback method <code>onAuthenticationSucceeded(FingerprintManager.AuthenticationResult result)</code> is called at which point, the authenticated <code>CryptoObject</code> can be retrieved from the result.

```java
public void authenticationSucceeded(FingerprintManager.AuthenticationResult result) {
	cipher = result.getCryptoObject().getCipher();

	(... do something with the authenticated cipher object ...)
}
```

It is important to remember that keys stored on hardware may not be secure so the following method for validating the integrity of the data is critical:

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
