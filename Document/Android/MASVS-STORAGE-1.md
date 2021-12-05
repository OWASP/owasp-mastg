## Testing MSTG-STORAGE-1

### [TC-1] Testing Local Storage for Sensitive Data

#### Overview

This test case focuses on identifying potentially sensitive data stored by an application and verifying if it is securely stored.
In general sensitive data stored locally on the device should always be at least encrypted, and any keys used for encryption methods should be securely stored within the Android Keystore. These files should also be stored within the application sandbox. If achievable for the application, sensitive data should be stored off device or, even better, not stored at all.

#### Static Analysis

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

### [TC-2] Testing Bad Practices

#### Overview

Encryption should be implemented using proven SDK functions. The following describes bad practices to look for in the source code:

#### Static Analysis

- Locally stored sensitive information "encrypted" via simple bit operations like XOR or bit flipping. These operations should be avoided because the encrypted data can be recovered easily.
- Keys used or created without Android onboard features, such as the Android KeyStore
- Keys disclosed by hard-coding

A typical misuse are hard-coded cryptographic keys. Hard-coded and world-readable cryptographic keys significantly increase the possibility that encrypted data will be recovered. Once an attacker obtains the data, decrypting it is trivial. Symmetric cryptography keys must be stored on the device, so identifying them is just a matter of time and effort. Consider the following code:

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

  ```default
  buildTypes {
    debug {
      minifyEnabled true
      buildConfigField "String", "hiddenPassword", "\"${hiddenPassword}\""
    }
  }
  ```

#### Dynamic Analysis

Install and use the app, executing all functions at least once. Data can be generated when entered by the user, sent by the endpoint, or shipped with the app. Then complete the following:

- Check both internal and external local storage for any files created by the application that contain sensitive data.
- Identify development files, backup files, and old files that shouldn't be included with a production release.
- Determine whether SQLite databases are available and whether they contain sensitive information. SQLite databases are stored in `/data/data/<package-name>/databases`.
- Identify if SQLite databases are encrypted. If so, determine how the database password is generated and stored and if this is sufficiently protected as described in the "[Storing a Key](#storing-a-key)" section of the Keystore overview.
- Check Shared Preferences that are stored as XML files (in `/data/data/<package-name>/shared_prefs`) for sensitive information. Shared Preferences are insecure and unencrypted by default. Some apps might opt to use [secure-preferences](https://github.com/scottyab/secure-preferences "Secure-preferences encrypts the values of Shared Preferences") to encrypt the values stored in Shared Preferences.
- Check the permissions of the files in `/data/data/<package-name>`. Only the user and group created when you installed the app (e.g., u0_a82) should have user read, write, and execute permissions (`rwx`). Other users should not have permission to access files, but they may have execute permissions for directories.
- Check for the usage of any Firebase Real-time databases and attempt to identify if they are misconfigured by making the following network call:
  - `https://_firebaseProjectName_.firebaseio.com/.json`
- Determine whether a Realm database is available in `/data/data/<package-name>/files/`, whether it is unencrypted, and whether it contains sensitive information. By default, the file extension is `realm` and the file name is `default`. Inspect the Realm database with the [Realm Browser](https://github.com/realm/realm-browser-osx "Realm Browser for macOS").