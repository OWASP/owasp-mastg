---
masvs_v1_id:
- MSTG-STORAGE-1
- MSTG-STORAGE-2
masvs_v2_id:
- MASVS-STORAGE-1
platform: android
title: Testing Local Storage for Sensitive Data
masvs_v1_levels:
- L1
- L2
profiles: [L1, L2]
status: deprecated
covered_by: [MASTG-TEST-0207, MASTG-TEST-0200, MASTG-TEST-0201, MASTG-TEST-0202]
deprecation_note: New version available in MASTG V2
---

## Overview

This test case focuses on identifying potentially sensitive data stored by an application and verifying if it is securely stored. The following checks should be performed:

- Analyze data storage in the source code.
- Be sure to trigger all possible functionality in the application (e.g. by clicking everywhere possible) in order to ensure data generation.
- Check all application generated and modified files and ensure that the storage method is sufficiently secure.
    - This includes `SharedPreferences`, databases, Internal Storage, External Storage, etc.

**NOTE:** For MASVS L1 compliance, it is sufficient to store data unencrypted in the application's internal storage directory (sandbox). For L2 compliance, additional encryption is required using cryptographic keys securely managed in the Android KeyStore. This includes using envelope encryption (DEK+KEK) or equivalent methods, or using the Android Security Library's [`EncryptedFile`](https://developer.android.com/reference/androidx/security/crypto/EncryptedFile)/[`EncryptedSharedPreferences`](https://developer.android.com/reference/androidx/security/crypto/EncryptedSharedPreferences).

!!! Warning

    The **Jetpack security crypto library**, including the `EncryptedFile` and  `EncryptedSharedPreferences` classes, has been [deprecated](https://developer.android.com/privacy-and-security/cryptography#jetpack_security_crypto_library). However, since an official replacement has not yet been released, we recommend using these classes until one is available.

## Static Analysis

First of all, try to determine the kind of storage used by the Android app and to find out whether the app processes sensitive data insecurely.

- Check `AndroidManifest.xml` for read/write external storage permissions, for example, `uses-permission android:name="android.permission.WRITE_EXTERNAL_STORAGE"`.
- Check the source code for keywords and API calls that are used to store data:
    - File permissions, such as:
        - `MODE_WORLD_READABLE` or `MODE_WORLD_WRITABLE`: You should avoid using `MODE_WORLD_WRITEABLE` and `MODE_WORLD_READABLE` for files because any app will be able to read from or write to the files, even if they are stored in the app's private data directory. If data must be shared with other applications, consider a content provider. A content provider offers read and write permissions to other apps and can grant dynamic permission on a case-by-case basis.
    - Classes and functions, such as:
        - the `SharedPreferences` class ( stores key-value pairs)
        - the `FileOutPutStream` class (uses internal or external storage)
        - the `getExternal*` functions (use external storage)
        - the `getWritableDatabase` function (returns a SQLiteDatabase for writing)
        - the `getReadableDatabase` function (returns a SQLiteDatabase for reading)
        - the `getCacheDir` and `getExternalCacheDirs` function (use cached files)

Encryption should be implemented using proven SDK functions. The following describes bad practices to look for in the source code:

- Locally stored sensitive information "encrypted" via simple bit operations like XOR or bit flipping. These operations should be avoided because the encrypted data can be recovered easily.
- Keys used or created without Android onboard features, such as the Android KeyStore
- Keys disclosed by hard-coding

A typical misuse are hard-coded cryptographic keys. Hard-coded and world-readable cryptographic keys significantly increase the possibility that encrypted data will be recovered. Once an attacker obtains the data, decrypting it is trivial. Symmetric cryptography keys must be stored on the device, so identifying them is just a matter of time and effort. Consider the following code:

```java
this.db = localUserSecretStore.getWritableDatabase("SuperPassword123");
```

Obtaining the key is trivial because it is contained in the source code and identical for all installations of the app. Encrypting data this way is not beneficial. Look for hard-coded API keys/private keys and other valuable data; they pose a similar risk. Encoded/encrypted keys represent another attempt to make it harder but not impossible to get the crown jewels.

Consider the following code:

Example in Java:

```java
//A more complicated effort to store the XOR'ed halves of a key (instead of the key itself)
private static final String[] myCompositeKey = new String[]{
  "oNQavjbaNNSgEqoCkT9Em4imeQQ=","3o8eFOX4ri/F8fgHgiy/BS47"
};
```

Example in Kotlin:

```kotlin
private val myCompositeKey = arrayOf<String>("oNQavjbaNNSgEqoCkT9Em4imeQQ=", "3o8eFOX4ri/F8fgHgiy/BS47")
```

The algorithm for decoding the original key might be something like this:

Example in Java:

```java
public void useXorStringHiding(String myHiddenMessage) {
  byte[] xorParts0 = Base64.decode(myCompositeKey[0],0);
  byte[] xorParts1 = Base64.decode(myCompositeKey[1],0);

  byte[] xorKey = new byte[xorParts0.length];
  for(int i = 0; i < xorParts1.length; i++){
    xorKey[i] = (byte) (xorParts0[i] ^ xorParts1[i]);
  }
  HidingUtil.doHiding(myHiddenMessage.getBytes(), xorKey, false);
}
```

Example in Kotlin:

```kotlin
fun useXorStringHiding(myHiddenMessage:String) {
  val xorParts0 = Base64.decode(myCompositeKey[0], 0)
  val xorParts1 = Base64.decode(myCompositeKey[1], 0)
  val xorKey = ByteArray(xorParts0.size)
  for (i in xorParts1.indices)
  {
    xorKey[i] = (xorParts0[i] xor xorParts1[i]).toByte()
  }
  HidingUtil.doHiding(myHiddenMessage.toByteArray(), xorKey, false)
}
```

Verify common locations of secrets:

- resources (typically at res/values/strings.xml)
  Example:

  ```xml
  <resources>
      <string name="app_name">SuperApp</string>
      <string name="hello_world">Hello world!</string>
      <string name="action_settings">Settings</string>
      <string name="secret_key">My_Secret_Key</string>
    </resources>
  ```

- build configs, such as in local.properties or gradle.properties
  Example:

  ```json
  buildTypes {
    debug {
      minifyEnabled true
      buildConfigField "String", "hiddenPassword", "\"${hiddenPassword}\""
    }
  }
  ```

## Dynamic Analysis

Install and use the app, executing all functions at least once. Data can be generated when entered by the user, sent by the endpoint, or shipped with the app. Then complete the following:

- Check both internal and external local storage for any files created by the application that contain sensitive data.
- Identify development files, backup files, and old files that shouldn't be included with a production release.
- Determine whether SQLite databases are available and whether they contain sensitive information. SQLite databases are stored in `/data/data/<package-name>/databases`.
- Identify if SQLite databases are encrypted. If so, determine how the database password is generated and stored and if this is sufficiently protected as described in the "[Storing a Key](../../../Document/0x05d-Testing-Data-Storage.md#storing-a-cryptographic-key-techniques)" section of the Keystore overview.
- Check Shared Preferences that are stored as XML files (in `/data/data/<package-name>/shared_prefs`) for sensitive information. Shared Preferences are insecure and unencrypted by default. Some apps might opt to use [secure-preferences](https://github.com/scottyab/secure-preferences "Secure-preferences encrypts the values of Shared Preferences") to encrypt the values stored in Shared Preferences.
- Check the permissions of the files in `/data/data/<package-name>`. Only the user and group created when you installed the app (e.g., u0_a82) should have user read, write, and execute permissions (`rwx`). Other users should not have permission to access files, but they may have execute permissions for directories.
- Check for the usage of any Firebase Real-time databases and attempt to identify if they are misconfigured by making the following network call:
    - `https://_firebaseProjectName_.firebaseio.com/.json`
- Determine whether a Realm database is available in `/data/data/<package-name>/files/`, whether it is unencrypted, and whether it contains sensitive information. By default, the file extension is `realm` and the file name is `default`. Inspect the Realm database with the [Realm Browser](https://github.com/realm/realm-browser-osx "Realm Browser for macOS").
