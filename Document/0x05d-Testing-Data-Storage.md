---
masvs_category: MASVS-STORAGE
platform: android
---

# Android Data Storage

## Overview

This chapter discusses the importance of securing sensitive data, like authentication tokens and private information, vital for mobile security. We'll look at Android's APIs for local data storage and share best practices.

While it's preferable to limit sensitive data on local storage, or avoid it at all whenever possible, practical use cases often necessitate user data storage. For example, to improve user experience, apps cache authentication tokens locally, circumventing the need for complex password entry at each app start. Apps may also need to store personally identifiable information (PII) and other sensitive data.

Sensitive data can become vulnerable if improperly protected, potentially stored in various locations, including the device or an external SD card. It's important to identify the information processed by the mobile app and classify what counts as sensitive data. Check out the "[Identifying Sensitive Data](0x04b-Mobile-App-Security-Testing.md#identifying-sensitive-data "Identifying Sensitive Data")" section in the "Mobile App Security Testing" chapter for data classification details. Refer to [Security Tips for Storing Data](https://developer.android.com/training/articles/security-tips.html#StoringData "Security Tips for Storing Data") in the Android developer's guide for comprehensive insights.

Sensitive information disclosure risks include potential information decryption, social engineering attacks (if PII is disclosed), account hijacking (if session information or an authentication token is disclosed), and app exploitation with a payment option.

In addition to data protection, validate and sanitize data from any storage source. This includes checking correct data types and implementing cryptographic controls, such as HMACs, for data integrity.

Android offers various [data storage](https://developer.android.com/training/data-storage "Storing Data in Android") methods, tailored to users, developers, and applications. Common persistent storage techniques include:

- Shared Preferences
- SQLite Databases
- Firebase Databases
- Realm Databases
- Internal Storage
- External Storage
- Keystore

Additionally, other Android functions that can result in data storage and should be tested include:

- Logging Functions
- Android Backups
- Processes Memory
- Keyboard Caches
- Screenshots

Understanding each relevant data storage function is crucial for performing the appropriate test cases. This overview provides a brief outline of these data storage methods and points testers to further relevant documentation.

### Shared Preferences

The [SharedPreferences](https://developer.android.com/training/data-storage/shared-preferences "Shared Preferences") API is commonly used to permanently save small collections of key-value pairs. Data stored in a SharedPreferences object is written to a plain-text XML file. The SharedPreferences object can be declared world-readable (accessible to all apps) or private.
Misuse of the SharedPreferences API can often lead to exposure of sensitive data. Consider the following example:

Example for Java:

```java
SharedPreferences sharedPref = getSharedPreferences("key", MODE_WORLD_READABLE);
SharedPreferences.Editor editor = sharedPref.edit();
editor.putString("username", "administrator");
editor.putString("password", "supersecret");
editor.commit();
```

Example for Kotlin:

```kotlin
var sharedPref = getSharedPreferences("key", Context.MODE_WORLD_READABLE)
var editor = sharedPref.edit()
editor.putString("username", "administrator")
editor.putString("password", "supersecret")
editor.commit()
```

Once the activity has been called, the file key.xml will be created with the provided data. This code violates several best practices.

- The username and password are stored in clear text in `/data/data/<package-name>/shared_prefs/key.xml`.

```xml
<?xml version='1.0' encoding='utf-8' standalone='yes' ?>
<map>
  <string name="username">administrator</string>
  <string name="password">supersecret</string>
</map>
```

- `MODE_WORLD_READABLE` allows all applications to access and read the contents of `key.xml`.

```bash
root@hermes:/data/data/sg.vp.owasp_mobile.myfirstapp/shared_prefs # ls -la
-rw-rw-r-- u0_a118    170 2016-04-23 16:51 key.xml
```

> Please note that `MODE_WORLD_READABLE` and `MODE_WORLD_WRITEABLE` were deprecated starting on API level 17. Although newer devices may not be affected by this, applications compiled with an `android:targetSdkVersion` value less than 17 may be affected if they run on an OS version that was released before Android 4.2 (API level 17).

### Databases

The Android platform provides a number of database options as aforementioned in the previous list. Each database option has its own quirks and methods that need to be understood.

### SQLite Database (Unencrypted)

SQLite is an SQL database engine that stores data in `.db` files. The Android SDK has [built-in support](https://developer.android.com/training/data-storage/sqlite "SQLite Documentation") for SQLite databases. The main package used to manage the databases is `android.database.sqlite`.
For example, you may use the following code to store sensitive information within an activity:

Example in Java:

```java
SQLiteDatabase notSoSecure = openOrCreateDatabase("privateNotSoSecure", MODE_PRIVATE, null);
notSoSecure.execSQL("CREATE TABLE IF NOT EXISTS Accounts(Username VARCHAR, Password VARCHAR);");
notSoSecure.execSQL("INSERT INTO Accounts VALUES('admin','AdminPass');");
notSoSecure.close();
```

Example in Kotlin:

```kotlin
var notSoSecure = openOrCreateDatabase("privateNotSoSecure", Context.MODE_PRIVATE, null)
notSoSecure.execSQL("CREATE TABLE IF NOT EXISTS Accounts(Username VARCHAR, Password VARCHAR);")
notSoSecure.execSQL("INSERT INTO Accounts VALUES('admin','AdminPass');")
notSoSecure.close()
```

Once the activity has been called, the database file `privateNotSoSecure` will be created with the provided data and stored in the clear text file `/data/data/<package-name>/databases/privateNotSoSecure`.

The database's directory may contain several files besides the SQLite database:

- [Journal files](https://www.sqlite.org/tempfiles.html "SQLite Journal files"): These are temporary files used to implement atomic commit and rollback.
- [Lock files](https://www.sqlite.org/lockingv3.html "SQLite Lock Files"): The lock files are part of the locking and journaling feature, which was designed to improve SQLite concurrency and reduce the writer starvation problem.

Sensitive information should not be stored in unencrypted SQLite databases.

### SQLite Databases (Encrypted)

With the library [SQLCipher](https://www.zetetic.net/sqlcipher/sqlcipher-for-android/ "SQLCipher"), you can password-encrypt SQLite databases.

Example in Java:

```java
SQLiteDatabase secureDB = SQLiteDatabase.openOrCreateDatabase(database, "password123", null);
secureDB.execSQL("CREATE TABLE IF NOT EXISTS Accounts(Username VARCHAR,Password VARCHAR);");
secureDB.execSQL("INSERT INTO Accounts VALUES('admin','AdminPassEnc');");
secureDB.close();
```

Example in Kotlin:

```kotlin
var secureDB = SQLiteDatabase.openOrCreateDatabase(database, "password123", null)
secureDB.execSQL("CREATE TABLE IF NOT EXISTS Accounts(Username VARCHAR,Password VARCHAR);")
secureDB.execSQL("INSERT INTO Accounts VALUES('admin','AdminPassEnc');")
secureDB.close()
```

Secure ways to retrieve the database key include:

- Asking the user to decrypt the database with a PIN or password once the app is opened (weak passwords and PINs are vulnerable to brute force attacks)
- Storing the key on the server and allowing it to be accessed from a web service only (so that the app can be used only when the device is online)

### Firebase Real-time Databases

Firebase is a development platform with more than 15 products, and one of them is Firebase Real-time Database. It can be leveraged by application developers to store and sync data with a NoSQL cloud-hosted database. The data is stored as JSON and is synchronized in real-time to every connected client and also remains available even when the application goes offline.

A misconfigured Firebase instance can be identified by making the following network call:

`https://_firebaseProjectName_.firebaseio.com/.json`

The _firebaseProjectName_ can be retrieved from the mobile application by reverse engineering the application. Alternatively, the analysts can use [Firebase Scanner](https://github.com/shivsahni/FireBaseScanner "Firebase Scanner"), a python script that automates the task above as shown below:

```bash
python FirebaseScanner.py -p <pathOfAPKFile>

python FirebaseScanner.py -f <commaSeparatedFirebaseProjectNames>
```

### Realm Databases

The [Realm Database for Java](https://mongodb.com/docs/realm/sdk/java/ "Realm Database") is becoming more and more popular among developers. The database and its contents can be encrypted with a key stored in the configuration file.

```java
//the getKey() method either gets the key from the server or from a KeyStore, or is derived from a password.
RealmConfiguration config = new RealmConfiguration.Builder()
  .encryptionKey(getKey())
  .build();

Realm realm = Realm.getInstance(config);

```

If the database _is not_ encrypted, you should be able to obtain the data. If the database _is_ encrypted, determine whether the key is hard-coded in the source or resources and whether it is stored unprotected in shared preferences or some other location.

### Internal Storage

You can save files to the device's [internal storage](https://developer.android.com/training/data-storage#filesInternal "Using Internal Storage"). Files saved to internal storage are containerized by default and cannot be accessed by other apps on the device. When the user uninstalls your app, these files are removed.
The following code snippets would persistently store sensitive data to internal storage.

Example for Java:

```java
FileOutputStream fos = null;
try {
   fos = openFileOutput(FILENAME, Context.MODE_PRIVATE);
   fos.write(test.getBytes());
   fos.close();
} catch (FileNotFoundException e) {
   e.printStackTrace();
} catch (IOException e) {
   e.printStackTrace();
}
```

Example for Kotlin:

```kotlin
var fos: FileOutputStream? = null
fos = openFileOutput("FILENAME", Context.MODE_PRIVATE)
fos.write(test.toByteArray(Charsets.UTF_8))
fos.close()
```

You should check the file mode to make sure that only the app can access the file. You can set this access with `MODE_PRIVATE`. Modes such as `MODE_WORLD_READABLE` (deprecated) and `MODE_WORLD_WRITEABLE` (deprecated) may pose a security risk.

Search for the class `FileInputStream` to find out which files are opened and read within the app.

### External Storage

Every Android-compatible device supports [shared external storage](https://developer.android.com/training/data-storage#filesExternal "Using External Storage"). This storage may be removable (such as an SD card) or internal (non-removable).
Files saved to external storage are world-readable. The user can modify them when USB mass storage is enabled.
You can use the following code snippets to persistently store sensitive information to external storage as the contents of the file `password.txt`.

Example for Java:

```java
File file = new File (Environment.getExternalFilesDir(), "password.txt");
String password = "SecretPassword";
FileOutputStream fos;
    fos = new FileOutputStream(file);
    fos.write(password.getBytes());
    fos.close();
```

Example for Kotlin:

```kotlin
val password = "SecretPassword"
val path = context.getExternalFilesDir(null)
val file = File(path, "password.txt")
file.appendText(password)
```

The file will be created and the data will be stored in a clear text file in external storage once the activity has been called.

It's also worth knowing that files stored outside the application folder (`data/data/<package-name>/`) will not be deleted when the user uninstalls the application.
Finally, it's worth noting that the external storage can be used by an attacker to allow for arbitrary control of the application in some cases. For more information: [see the blog post from Checkpoint](https://blog.checkpoint.com/2018/08/12/man-in-the-disk-a-new-attack-surface-for-android-apps/ "Man in the disk").

### KeyStore

The [Android KeyStore](https://www.androidauthority.com/use-android-keystore-store-passwords-sensitive-information-623779/ "Use Android KeyStore") supports relatively secure credential storage. As of Android 4.3 (API level 18), it provides public APIs for storing and using app-private keys. An app can use a public key to create a new private/public key pair for encrypting application secrets, and it can decrypt the secrets with the private key.

You can protect keys stored in the Android KeyStore with user authentication in a confirm credential flow. The user's lock screen credentials (pattern, PIN, password, or fingerprint) are used for authentication.

You can use stored keys in one of two modes:

1. Users are authorized to use keys for a limited period of time after authentication. In this mode, all keys can be used as soon as the user unlocks the device. You can customize the period of authorization for each key. You can use this option only if the secure lock screen is enabled. If the user disables the secure lock screen, all stored keys will become permanently invalid.

2. Users are authorized to use a specific cryptographic operation that is associated with one key. In this mode, users must request a separate authorization for each operation that involves the key. Currently, fingerprint authentication is the only way to request such authorization.

The level of security afforded by the Android KeyStore depends on its implementation, which depends on the device. Most modern devices offer a [hardware-backed KeyStore implementation](0x05d-Testing-Data-Storage.md#hardware-backed-android-keyStore): keys are generated and used in a Trusted Execution Environment (TEE) or a Secure Element (SE), and the operating system can't access them directly. This means that the encryption keys themselves can't be easily retrieved, even from a rooted device. You can verify hardware-backed keys with [Key Attestation](0x05d-Testing-Data-Storage.md#key-attestation). You can determine whether the keys are inside the secure hardware by checking the return value of the `isInsideSecureHardware` method, which is part of the [`KeyInfo` class](https://developer.android.com/reference/android/security/keystore/KeyInfo.html "Class KeyInfo").

>Note that the relevant KeyInfo indicates that secret keys and HMAC keys are insecurely stored on several devices despite private keys being correctly stored on the secure hardware.

The keys of a software-only implementation are encrypted with a [per-user encryption master key](https://nelenkov.blogspot.sg/2013/08/credential-storage-enhancements-android-43.html "Nikolay Elenvok - Credential storage enhancements in Android 4.3"). An attacker can access all keys stored on rooted devices that have this implementation in the folder `/data/misc/keystore/`. Because the user's lock screen pin/password is used to generate the master key, the Android KeyStore is unavailable when the device is locked. For more security Android 9 (API level 28) introduces the `unlockedDeviceRequired` flag. By passing `true` to the `setUnlockedDeviceRequired` method, the app prevents its keys stored in `AndroidKeystore` from being decrypted when the device is locked, and it requires the screen to be unlocked before allowing decryption.

### Hardware-backed Android KeyStore

The hardware-backed Android KeyStore gives another layer to defense-in-depth security concept for Android. Keymaster Hardware Abstraction Layer (HAL) was introduced with Android 6 (API level 23). Applications can verify if the key is stored inside the security hardware (by checking if `KeyInfo.isinsideSecureHardware` returns `true`). Devices running Android 9 (API level 28) and higher can have a `StrongBox Keymaster` module, an implementation of the Keymaster HAL that resides in a hardware security module which has its own CPU, secure storage, a true random number generator and a mechanism to resist package tampering. To use this feature, `true` must be passed to the `setIsStrongBoxBacked` method in either the `KeyGenParameterSpec.Builder` class or the `KeyProtection.Builder` class when generating or importing keys using `AndroidKeystore`. To make sure that StrongBox is used during runtime, check that `isInsideSecureHardware` returns `true` and that the system does not throw `StrongBoxUnavailableException`, which gets thrown if the StrongBox Keymaster isn't available for the given algorithm and key size associated with a key. Description of features on hardware-based keystore can be found on [AOSP pages](https://source.android.com/docs/security/features/keystore "AOSP Hardware-based KeyStore").

Keymaster HAL is an interface to hardware-backed components - Trusted Execution Environment (TEE) or a Secure Element (SE), which is used by Android Keystore. An example of such a hardware-backed component is [Titan M](https://android-developers.googleblog.com/2018/10/building-titan-better-security-through.html "Building a Titan: Better security through a tiny chip").

### Key Attestation

For the applications which heavily rely on Android Keystore for business-critical operations, such as multi-factor authentication through cryptographic primitives, secure storage of sensitive data at the client-side, etc. Android provides the feature of [Key Attestation](https://developer.android.com/training/articles/security-key-attestation "Key Attestation"), which helps to analyze the security of cryptographic material managed through Android Keystore. From Android 8.0 (API level 26), the key attestation was made mandatory for all new (Android 7.0 or higher) devices that need to have device certification for Google apps. Such devices use attestation keys signed by the [Google hardware Attestation Root certificate](https://developer.android.com/training/articles/security-key-attestation#root_certificate "Google Hardware Attestation Root Certificate") and the same can be verified through the key attestation process.

During key attestation, we can specify the alias of a key pair and in return, get a certificate chain, which we can use to verify the properties of that key pair. If the root certificate of the chain is the [Google Hardware Attestation Root certificate](https://developer.android.com/training/articles/security-key-attestation#root_certificate "Google Hardware Attestation Root certificate"), and the checks related to key pair storage in hardware are made, it gives an assurance that the device supports hardware-level key attestation, and that the key is in the hardware-backed keystore that Google believes to be secure. Alternatively, if the attestation chain has any other root certificate, then Google does not make any claims about the security of the hardware.

Although the key attestation process can be implemented within the application directly, it is recommended that it should be implemented at the server-side for security reasons. The following are the high-level guidelines for the secure implementation of Key Attestation:

- The server should initiate the key attestation process by creating a random number securely using CSPRNG (Cryptographically Secure Random Number Generator) and the same should be sent to the user as a challenge.
- The client should call the `setAttestationChallenge` API with the challenge received from the server and should then retrieve the attestation certificate chain using the `KeyStore.getCertificateChain` method.
- The attestation response should be sent to the server for the verification and following checks should be performed for the verification of the key attestation response:
    - Verify the certificate chain, up to the root and perform certificate sanity checks such as validity, integrity and trustworthiness. Check the [Certificate Revocation Status List](https://developer.android.com/training/articles/security-key-attestation#certificate_status "Certificate Revocation Status List") maintained by Google, if none of the certificates in the chain was revoked.
    - Check if the root certificate is signed with the Google attestation root key which makes the attestation process trustworthy.
    - Extract the attestation [certificate extension data](https://developer.android.com/training/articles/security-key-attestation#certificate_schema "Certificate extension data schema"), which appears within the first element of the certificate chain, and perform the following checks:
        - Verify that the attestation challenge is having the same value which was generated at the server while initiating the attestation process.
        - Verify the signature in the key attestation response.
        - Verify the security level of the Keymaster, to determine if the device has secure key storage mechanism. Keymaster is a piece of software that runs in the security context and provides all the secure keystore operations. The security level will be one of `Software`, `TrustedEnvironment` or `StrongBox`. The client supports hardware-level key attestation if the security level is `TrustedEnvironment` or `StrongBox` and the attestation certificate chain contains a root certificate signed with the Google attestation root key.
        - Verify the client's status to ensure a full chain of trust - verified boot key, locked bootloader and verified boot state.
        - Additionally, you can verify the key pair's attributes such as purpose, access time, authentication requirement, etc.

> Note, if for any reason that process fails, it means that the key is not in security hardware. That does not mean that the key is compromised.

The typical example of Android Keystore attestation response looks like this:

```json
{
    "fmt": "android-key",
    "authData": "9569088f1ecee3232954035dbd10d7cae391305a2751b559bb8fd7cbb229bd...",
    "attStmt": {
        "alg": -7,
        "sig": "304402202ca7a8cfb6299c4a073e7e022c57082a46c657e9e53...",
        "x5c": [
            "308202ca30820270a003020102020101300a06082a8648ce3d040302308188310b30090603550406130...",
            "308202783082021ea00302010202021001300a06082a8648ce3d040302308198310b300906035504061...",
            "3082028b30820232a003020102020900a2059ed10e435b57300a06082a8648ce3d040302308198310b3..."
        ]
    }
}
```

In the above JSON snippet, the keys have the following meaning:

- `fmt`: Attestation statement format identifier
- `authData`: It denotes the authenticator data for the attestation
- `alg`: The algorithm that is used for the Signature
- `sig`: Signature
- `x5c`: Attestation certificate chain

> Note: The `sig` is generated by concatenating `authData` and `clientDataHash` (challenge sent by the server) and signing through the credential private key using the `alg` signing algorithm. The same is verified at the server-side by using the public key in the first certificate.

For more understanding on the implementation guidelines, you can refer to [Google Sample Code](https://github.com/googlesamples/android-key-attestation/blob/master/server/src/main/java/com/android/example/KeyAttestationExample.java "Google Sample Code For Android Key Attestation").

For the security analysis perspective, the analysts may perform the following checks for the secure implementation of Key Attestation:

- Check if the key attestation is totally implemented on the client-side. In which case, it can be more easily bypassed by tampering the application, method hooking, etc.
- Check if the server uses random challenge while initiating the key attestation. As failing to do that would lead to insecure implementation thus making it vulnerable to replay attacks. Also, checks pertaining to the randomness of the challenge should be performed.
- Check if the server verifies the integrity of the key attestation response.
- Check if the server performs basic checks such as integrity verification, trust verification, validity, etc. on the certificates in the chain.

### Secure Key Import into Keystore

Android 9 (API level 28) adds the ability to import keys securely into the `AndroidKeystore`. First, `AndroidKeystore` generates a key pair using `PURPOSE_WRAP_KEY`, which should also be protected with an attestation certificate. This pair aims to protect the Keys being imported to `AndroidKeystore`. The encrypted keys are generated as ASN.1-encoded message in the `SecureKeyWrapper` format, which also contains a description of the ways the imported key is allowed to be used. The keys are then decrypted inside the `AndroidKeystore` hardware belonging to the specific device that generated the wrapping key, so that they never appear as plaintext in the device's host memory.

<img src="Images/Chapters/0x05d/Android9_secure_key_import_to_keystore.jpg" alt="Secure key import into Keystore" width="500px"/>

Example in Java:

```java
KeyDescription ::= SEQUENCE {
    keyFormat INTEGER,
    authorizationList AuthorizationList
}

SecureKeyWrapper ::= SEQUENCE {
    wrapperFormatVersion INTEGER,
    encryptedTransportKey OCTET_STRING,
    initializationVector OCTET_STRING,
    keyDescription KeyDescription,
    secureKey OCTET_STRING,
    tag OCTET_STRING
}
```

The code above presents the different parameters to be set when generating the encrypted keys in the SecureKeyWrapper format. Check the Android documentation on [`WrappedKeyEntry`](https://developer.android.com/reference/android/security/keystore/WrappedKeyEntry "WrappedKeyEntry") for more details.

When defining the KeyDescription AuthorizationList, the following parameters will affect the encrypted keys security:

- The `algorithm` parameter specifies the cryptographic algorithm with which the key is used
- The `keySize` parameter specifies the size, in bits, of the key, measuring in the normal way for the key's algorithm
- The `digest` parameter specifies the digest algorithms that may be used with the key to perform signing and verification operations

### Older KeyStore Implementations

Older Android versions don't include KeyStore, but they _do_ include the KeyStore interface from JCA (Java Cryptography Architecture). You can use KeyStores that implement this interface to ensure the secrecy and integrity of keys stored with KeyStore; BouncyCastle KeyStore (BKS) is recommended. All implementations are based on the fact that files are stored on the filesystem; all files are password-protected.
To create one, use the `KeyStore.getInstance("BKS", "BC") method`, where "BKS" is the KeyStore name (BouncyCastle Keystore) and "BC" is the provider (BouncyCastle). You can also use SpongyCastle as a wrapper and initialize the KeyStore as follows: `KeyStore.getInstance("BKS", "SC")`.

Be aware that not all KeyStores properly protect the keys stored in the KeyStore files.

### Storing a Cryptographic Key: Techniques

To mitigate unauthorized use of keys on the Android device, Android KeyStore lets apps specify authorized uses of their keys when generating or importing the keys. Once made, authorizations cannot be changed.

Storing a Key - from most secure to least secure:

- the key is stored in hardware-backed Android KeyStore
- all keys are stored on server and are available after strong authentication
- the master key is stored on the server and used to encrypt other keys, which are stored in Android SharedPreferences
- the key is derived each time from a strong user provided passphrase with sufficient length and salt
- the key is stored in the software implementation of Android KeyStore
- the master key is stored in the software implementation of Android Keystore and used to encrypt other keys, which are stored in SharedPreferences
- [not recommended] all keys are stored in SharedPreferences
- [not recommended] hardcoded encryption keys in the source code
- [not recommended] predictable obfuscation function or key derivation function based on stable attributes
- [not recommended] stored generated keys in public places (like `/sdcard/`)

#### Storing Keys Using Hardware-backed Android KeyStore

You can use the [hardware-backed Android KeyStore](0x05d-Testing-Data-Storage.md#hardware-backed-android-keystore) if the device is running Android 7.0 (API level 24) and above with available hardware component (Trusted Execution Environment (TEE) or a Secure Element (SE)). You can even verify that the keys are hardware-backed by using the guidelines provided for [the secure implementation of Key Attestation](0x05d-Testing-Data-Storage.md#key-attestation). If a hardware component is not available and/or support for Android 6.0 (API level 23) and below is required, then you might want to store your keys on a remote server and make them available after authentication.

#### Storing Keys on the Server

It is possible to securely store keys on a key management server, however the app needs to be online to decrypt the data. This might be a limitation for certain mobile app use cases and should be carefully thought through, as this becomes part of the architecture of the app and might highly impact usability.

#### Deriving Keys from User Input

Deriving a key from a user provided passphrase is a common solution (depending on which Android API level you use), but it also impacts usability, might affect the attack surface and could introduce additional weaknesses.

Each time the application needs to perform a cryptographic operation, the user's passphrase is needed. Either the user is prompted for it every time, which isn't an ideal user experience, or the passphrase is kept in memory as long as the user is authenticated. Keeping the passphrase in memory is not a best-practice, as any cryptographic material must only be kept in memory while it is being used. Zeroing out a key is often a very challenging task as explained in ["Cleaning out Key Material"](#cleaning-out-key-material).

Additionally, consider that keys derived from a passphrase have their own weaknesses. For instance, the passwords or passphrases might be reused by the user or easy to guess. Please refer to the [Testing Cryptography chapter](0x04g-Testing-Cryptography.md#weak-key-generation-functions) for more information.

#### Cleaning out Key Material

The key material should be cleared out from memory as soon as it is not need anymore. There are certain limitations of reliably cleaning up secret data in languages with garbage collector (Java) and immutable strings (Swift, Objective-C, Kotlin). [Java Cryptography Architecture Reference Guide](https://docs.oracle.com/en/java/javase/16/security/java-cryptography-architecture-jca-reference-guide.html#GUID-C9F76AFB-6B20-45A7-B84F-96756C8A94B4 "Java Cryptography Architecture (JCA) Reference Guide") suggests using `char[]` instead of `String` for storing sensitive data, and nullify array after usage.

Note that some ciphers do not properly clean up their byte-arrays. For instance, the AES Cipher in BouncyCastle does not always clean up its latest working key, leaving some copies of the byte-array in memory. Next, BigInteger based keys (e.g. private keys) cannot be removed from the heap, nor zeroed out without additional effort. Clearing byte array can be achieved by writing a wrapper which implements [Destroyable](https://docs.oracle.com/javase/8/docs/api/javax/security/auth/Destroyable.html#destroy--).

#### Storing Keys using Android KeyStore API

A more user-friendly and recommended way is to use the [Android KeyStore API](https://developer.android.com/reference/java/security/KeyStore.html "Android AndroidKeyStore API") system (itself or through KeyChain) to store key material. If it is possible, hardware-backed storage should be used. Otherwise, it should fallback to software implementation of Android Keystore. However, be aware that the `AndroidKeyStore` API has been changed significantly throughout versions of Android. In earlier versions, the `AndroidKeyStore` API only supported storing public/private key pairs (e.g., RSA). Symmetric key support has only been added since Android 6.0 (API level 23). As a result, a developer needs to handle the different Android API levels to securely store symmetric keys.

#### Storing keys by encrypting them with other keys

In order to securely store symmetric keys on devices running on Android 5.1 (API level 22) or lower, we need to generate a public/private key pair. We encrypt the symmetric key using the public key and store the private key in the `AndroidKeyStore`. The encrypted symmetric key can be encoded using base64 and stored in the `SharedPreferences`. Whenever we need the symmetric key, the application retrieves the private key from the `AndroidKeyStore` and decrypts the symmetric key.

Envelope encryption, or key wrapping, is a similar approach that uses symmetric encryption to encapsulate key material. Data encryption keys (DEKs) can be encrypted with key encryption keys (KEKs) which are securely stored. Encrypted DEKs can be stored in `SharedPreferences` or written to files. When required, the application reads the KEK, then decrypts the DEK. Refer to [OWASP Cryptographic Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html#encrypting-stored-keys "OWASP Cryptographic Storage Cheat Sheet: Encrypting Stored Keys") to learn more about encrypting cryptographic keys.

Also, as the illustration of this approach, refer to the [EncryptedSharedPreferences from androidx.security.crypto package](https://developer.android.com/jetpack/androidx/releases/security "androidx.security.crypto API reference").

#### Insecure options to store keys

A less secure way of storing encryption keys, is in the SharedPreferences of Android. When [SharedPreferences](https://developer.android.com/reference/android/content/SharedPreferences.html "Android SharedPreference API") are used, the file is only readable by the application that created it. However, on rooted devices, any other application with root access can read the SharedPreferences file of other apps. This is not the case for the AndroidKeyStore, since AndroidKeyStore access is managed on the kernel level, which needs considerably more work and skill to bypass without the AndroidKeyStore clearing or destroying the keys.

The last three options are to use hardcoded encryption keys in the source code, having a predictable obfuscation function or key derivation function based on stable attributes, and storing generated keys in public places like `/sdcard/`. Hardcoded encryption keys are an issue, since this means every instance of the application uses the same encryption key. An attacker can reverse-engineer a local copy of the application to extract the cryptographic key, and use that key to decrypt any data which was encrypted by the application on any device.

Next, when you have a predictable key derivation function based on identifiers which are accessible to other applications, the attacker only needs to find the KDF and apply it to the device to find the key. Lastly, storing encryption keys publicly is also highly discouraged, as other applications can have permission to read the public partition and steal the keys.

#### Data Encryption Using Third Party Libraries

There are several different open-source libraries that offer encryption capabilities specific to the Android platform.

- **[Java AES Crypto](https://github.com/tozny/java-aes-crypto "Java AES Crypto")** - A simple Android class for encrypting and decrypting strings.
- **[SQL Cipher](https://www.zetetic.net/sqlcipher/sqlcipher-for-android/ "SQL Cipher")** - SQLCipher is an open source extension to SQLite that provides transparent 256-bit AES encryption of database files.
- **[Themis](https://github.com/cossacklabs/themis "Themis cryptographic library")** - A cross-platform high-level cryptographic library that provides the same API across many platforms, for securing data during authentication, storage, messaging, etc.

> Please keep in mind that as long as the key is not stored in the KeyStore, it is always possible to easily retrieve the key on a rooted device and then decrypt the values you are trying to protect.

### KeyChain

The [KeyChain class](https://developer.android.com/reference/android/security/KeyChain.html "Android KeyChain") is used to store and retrieve _system-wide_ private keys and their corresponding certificates (chain). The user will be prompted to set a lock screen pin or password to protect the credential storage if something is being imported into the KeyChain for the first time. Note that the KeyChain is system-wide, every application can access the materials stored in the KeyChain.

Inspect the source code to determine whether native Android mechanisms identify sensitive information. Sensitive information should be encrypted, not stored in clear text. For sensitive information that must be stored on the device, several API calls are available to protect the data via the `KeyChain` class. Complete the following steps:

- Make sure that the app is using the Android KeyStore and Cipher mechanisms to securely store encrypted information on the device. Look for the patterns `AndroidKeystore`, `import java.security.KeyStore`, `import javax.crypto.Cipher`, `import java.security.SecureRandom`, and corresponding usages.
- Use the `store(OutputStream stream, char[] password)` function to store the KeyStore to disk with a password. Make sure that the password is provided by the user, not hard-coded.

### Logs

There are many legitimate reasons to create log files on a mobile device, such as keeping track of crashes, errors, and usage statistics. Log files can be stored locally when the app is offline and sent to the endpoint once the app is online. However, logging sensitive data may expose the data to attackers or malicious applications, and it might also violate user confidentiality.
You can create log files in several ways. The following list includes two classes that are available for Android:

- [Log Class](https://developer.android.com/reference/android/util/Log.html "Log Class")
- [Logger Class](https://developer.android.com/reference/java/util/logging/Logger.html "Logger Class")

### Backups

Android provides users with an auto-backup feature. The backups usually include copies of data and settings for all installed apps. Given its diverse ecosystem, Android supports many backup options:

- Stock Android has built-in USB backup facilities. When USB debugging is enabled, use the `adb backup` command to create full data backups and backups of an app's data directory.

- Google provides a "Back Up My Data" feature that backs up all app data to Google's servers.

- Two Backup APIs are available to app developers:
    - [Key/Value Backup](https://developer.android.com/guide/topics/data/keyvaluebackup.html "Key/Value Backup") (Backup API or Android Backup Service) uploads to the Android Backup Service cloud.

    - [Auto Backup for Apps](https://developer.android.com/guide/topics/data/autobackup.html "Auto Backup for Apps"): With Android 6.0 (API level 23) and above, Google added the "Auto Backup for Apps feature". This feature automatically syncs at most 25MB of app data with the user's Google Drive account.

- OEMs may provide additional options. For example, HTC devices have a "HTC Backup" option that performs daily backups to the cloud when activated.

Apps must carefully ensure that sensitive user data doesn't end within these backups as this may allow an attacker to extract it.

### ADB Backup Support

Android provides an attribute called [`allowBackup`](https://developer.android.com/guide/topics/manifest/application-element.html#allowbackup "allowBackup attribute") to back up all your application data. This attribute is set in the `AndroidManifest.xml` file. If the value of this attribute is **true**, the device allows users to back up the application with Android Debug Bridge (ADB) via the command `$ adb backup`.

To prevent the app data backup, set the `android:allowBackup` attribute to **false**. When this attribute is unavailable, the allowBackup setting is enabled by default, and backup must be manually deactivated.

> Note: If the device was encrypted, then the backup files will be encrypted as well.

### Process Memory

All applications on Android use memory to perform normal computational operations like any regular modern-day computer. It is of no surprise then that at times sensitive operations will be performed within process memory. For this reason, it is important that once the relevant sensitive data has been processed, it should be disposed from process memory as quickly as possible.

The investigation of an application's memory can be done from memory dumps, and from analyzing the memory in real time via a debugger.

For an overview of possible sources of data exposure, check the documentation and identify application components before you examine the source code. For example, sensitive data from a backend may be in the HTTP client, the XML parser, etc. You want all these copies to be removed from memory as soon as possible.

In addition, understanding the application's architecture and the architecture's role in the system will help you identify sensitive information that doesn't have to be exposed in memory at all. For example, assume your app receives data from one server and transfers it to another without any processing. That data can be handled in an encrypted format, which prevents exposure in memory.

However, if you need to expose sensitive data in memory, you should make sure that your app is designed to expose as few data copies as possible as briefly as possible. In other words, you want the handling of sensitive data to be centralized (i.e., with as few components as possible) and based on primitive, mutable data structures.

The latter requirement gives developers direct memory access. Make sure that they use this access to overwrite the sensitive data with dummy data (typically zeroes). Examples of preferable data types include `byte []` and `char []`, but not `String` or `BigInteger`. Whenever you try to modify an immutable object like `String`, you create and change a copy of the object.

Using non-primitive mutable types like `StringBuffer` and `StringBuilder` may be acceptable, but it's indicative and requires care. Types like `StringBuffer` are used to modify content (which is what you want to do). To access such a type's value, however, you would use the `toString` method, which would create an immutable copy of the data. There are several ways to use these data types without creating an immutable copy, but they require more effort than using a primitive array. Safe memory management is one benefit of using types like `StringBuffer` , but this can be a two-edged sword. If you try to modify the content of one of these types and the copy exceeds the buffer capacity, the buffer size will automatically increase. The buffer content may be copied to a different location, leaving the old content without a reference use to overwrite it.

Unfortunately, few libraries and frameworks are designed to allow sensitive data to be overwritten. For example, destroying a key, as shown below, doesn't remove the key from memory:

Example in Java:

```java
SecretKey secretKey = new SecretKeySpec("key".getBytes(), "AES");
secretKey.destroy();
```

Example in Kotlin:

```kotlin
val secretKey: SecretKey = SecretKeySpec("key".toByteArray(), "AES")
secretKey.destroy()
```

Overwriting the backing byte-array from `secretKey.getEncoded` doesn't remove the key either; the SecretKeySpec-based key returns a copy of the backing byte-array. See the sections below for the proper way to remove a `SecretKey` from memory.

The RSA key pair is based on the `BigInteger` type and therefore resides in memory after its first use outside the `AndroidKeyStore`. Some ciphers (such as the AES `Cipher` in `BouncyCastle`) do not properly clean up their byte-arrays.

User-provided data (credentials, social security numbers, credit card information, etc.) is another type of data that may be exposed in memory. Regardless of whether you flag it as a password field, `EditText` delivers content to the app via the `Editable` interface. If your app doesn't provide `Editable.Factory`, user-provided data will probably be exposed in memory for longer than necessary. The default `Editable` implementation, the `SpannableStringBuilder`, causes the same issues as Java's `StringBuilder` and `StringBuffer` cause (discussed above).

### Third-party Services Embedded in the App

The features provided by third-party services can involve tracking services to monitor the user's behavior while using the app, selling banner advertisements, or improving the user experience.

The downside is that developers don't usually know the details of the code executed via third-party libraries. Consequently, no more information than is necessary should be sent to a service, and no sensitive information should be disclosed.

Most third-party services are implemented in two ways:

- with a standalone library
- with a full SDK

### User Interface

### UI Components

At certain points in time, the user will have to enter sensitive information into the application. This data may be financial information such as credit card data or user account passwords, or maybe healthcare data. The data may be exposed if the app doesn't properly mask it while it is being typed.

In order to prevent disclosure and mitigate risks such as [shoulder surfing](https://en.wikipedia.org/wiki/Shoulder_surfing_%28computer_security%29) you should verify that no sensitive data is exposed via the user interface unless explicitly required (e.g. a password being entered). For the data required to be present it should be properly masked, typically by showing asterisks or dots instead of clear text.

### Screenshots

Manufacturers want to provide device users with an aesthetically pleasing experience at application startup and exit, so they introduced the screenshot-saving feature for use when the application is backgrounded. This feature may pose a security risk. Sensitive data may be exposed if the user deliberately screenshots the application while sensitive data is displayed. A malicious application that is running on the device and able to continuously capture the screen may also expose data. Screenshots are written to local storage, from which they may be recovered by a rogue application (if the device is rooted) or someone who has stolen the device.

For example, capturing a screenshot of a banking application may reveal information about the user's account, credit, transactions, and so on.

### App Notifications

It is important to understand that [notifications](https://developer.android.com/guide/topics/ui/notifiers/notifications "Notifications Overview") should never be considered private. When a notification is handled by the Android system it is broadcasted system-wide and any application running with a [NotificationListenerService](https://developer.android.com/reference/kotlin/android/service/notification/NotificationListenerService "NotificationListenerService") can listen for these notifications to receive them in full and may handle them however it wants.

There are many known malware samples such as [Joker](https://research.checkpoint.com/2020/new-joker-variant-hits-google-play-with-an-old-trick/ "Joker Malware"), and [Alien](https://www.threatfabric.com/blogs/alien_the_story_of_cerberus_demise.html "Alien Malware") which abuses the `NotificationListenerService` to listen for notifications on the device and then send them to attacker-controlled C2 infrastructure. Commonly this is done to listen for two-factor authentication (2FA) codes that appear as notifications on the device which are then sent to the attacker. A safer alternative for the user would be to use a 2FA application that does not generate notifications.

Furthermore there are a number of apps on the Google Play Store that provide notification logging, which logs locally any notifications on the Android system. This highlights that notifications are in no way private on Android and accessible by any other app on the device.

For this reason all notification usage should be inspected for confidential or high risk information that could be used by malicious applications.

### Keyboard Cache

When users enter information in input fields, the software automatically suggests data. This feature can be very useful for messaging apps. However, the keyboard cache may disclose sensitive information when the user selects an input field that takes this type of information.
