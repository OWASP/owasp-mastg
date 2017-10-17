## Testing Data Storage on Android

The protection of sensitive data, such as authentication tokens or private information, is a key focus in mobile security. In this chapter you will learn about the APIs Android offers for local data storage, as well as best practices for using them.

The credo for saving data can be summarized quite easily: Public data should be available for everybody, but sensitive and private data needs to be protected or even better not get stored on the device in the first place.

Note that "sensitive data" need to be identified in the context of each specific app. Data classification is described in detail in the chapter "Mobile App Security Testing" in section "Identifying Sensitive Data".

### Testing for Sensitive Data in Local Storage

#### Overview

Conventional wisdom suggests saving as little sensitive data as possible on permanent local storage. However, in most practical scenarios, at least some types of user-related data need to be stored. For example, asking the user to enter a highly complex password every time the app is started isn't a great idea from a usability perspective. As a result, most apps must locally cache some kind of authentication token. Other types of sensitive data, such as personally identifiable information (PII), might also be saved if the particular scenario calls for it.

A vulnerability occurs when sensitive data is not properly protected by an app when persistently storing it. The app might be able to store it in different places, for example locally on the device or on an external SD card. When trying to exploit these kinds of issues, consider that there might be a lot of information processed and stored in different locations. It is important to identify at the beginning what kind of information is processed by the mobile application and keyed in by the user and what might be interesting and valuable for an attacker (e.g. passwords, credit card information, PII).

Consequences for disclosing sensitive information can be various, like disclosure of encryption keys that can be used by an attacker to decrypt information. More generally speaking an attacker might be able to identify this information to use it as a basis for further attacks like social engineering (when PII is disclosed), account hijacking (if session information or an authentication token is disclosed) or gather information from apps that have a payment option in order to attack and abuse it.

[Storing data](https://developer.android.com/guide/topics/data/data-storage.html "Storing Data in Android") is essential for many mobile apps, for example in order to keep track of user settings or data a user has keyed in that needs to be stored locally or offline. Data can be stored persistently in various ways. The following list shows those mechanisms that are widely used on the Android platform:

- Shared Preferences
- SQLite Databases
- Realm Databases
- Internal Storage
- External Storage

The following snippets of code demonstrate bad practices that disclose sensitive information, but also show the different storage mechanisms on Android in detail. Please also check the [Security Tips data](http://developer.android.com/training/articles/security-tips.html#StoringData "Security Tips for Storing Data") in the Android developers guide.

##### Shared Preferences

[Shared Preferences](http://developer.android.com/reference/android/content/SharedPreferences.html "Shared Preferences") is a common approach to store Key/Value pairs persistently in the filesystem by using an XML structure. Within an activity the following code might be used to store sensitive information like a username and a password:

```java
SharedPreferences sharedPref = getSharedPreferences("key", MODE_WORLD_READABLE);
SharedPreferences.Editor editor = sharedPref.edit();
editor.putString("username", "administrator");
editor.putString("password", "supersecret");
editor.commit();
```

Once the activity is called, the file key.xml is created with the provided data. This code is violating several best practices.

- The username and password is stored in clear text in `/data/data/<package-name>/shared_prefs/key.xml`

```xml
<?xml version='1.0' encoding='utf-8' standalone='yes' ?>
<map>
  <string name="username">administrator</string>
  <string name="password">supersecret</string>
</map>
```

- `MODE_WORLD_READABLE` allows all applications to access and read the content of `key.xml`

```bash
root@hermes:/data/data/sg.vp.owasp_mobile.myfirstapp/shared_prefs # ls -la
-rw-rw-r-- u0_a118 u0_a118    170 2016-04-23 16:51 key.xml
```

> Please note that `MODE_WORLD_READABLE` and `MODE_WORLD_WRITEABLE` were deprecated in API 17. Although this may not affect newer devices, applications compiled with android:targetSdkVersion set prior to 17 may still be affected, if they run on OS prior to Android 4.2 (`JELLY_BEAN_MR1`).


##### SQLite Database (Unencrypted)

SQLite is a SQL database that stores data to a `.db` file. The Android SDK comes with built in support for SQLite databases. The main package to manage the databases is `android.database.sqlite`.
Within an activity the following code might be used to store sensitive information like a username and a password:

```java
SQLiteDatabase notSoSecure = openOrCreateDatabase("privateNotSoSecure",MODE_PRIVATE,null);
notSoSecure.execSQL("CREATE TABLE IF NOT EXISTS Accounts(Username VARCHAR, Password VARCHAR);");
notSoSecure.execSQL("INSERT INTO Accounts VALUES('admin','AdminPass');");
notSoSecure.close();
```

Once the activity is called, the database file `privateNotSoSecure` is created with the provided data and is stored in clear text in `/data/data/<package-name>/databases/privateNotSoSecure`.

There might be several files available in the databases directory, besides the SQLite database.

- [Journal files](https://www.sqlite.org/tempfiles.html "SQLite Journal files"): These are temporary files used to implement atomic commit and rollback capabilities in SQLite.
- [Lock files](https://www.sqlite.org/lockingv3.html "SQLite Lock Files"): The lock files are part of the locking and journaling mechanism designed to improve concurrency in SQLite and to reduce the writer starvation problem.

Unencrypted SQLite databases should not be used to store sensitive information.

##### SQLite Databases (Encrypted)

By using the library [SQLCipher](https://www.zetetic.net/sqlcipher/sqlcipher-for-android/ "SQLCipher") SQLite databases can be encrypted, by providing a password.

```java
SQLiteDatabase secureDB = SQLiteDatabase.openOrCreateDatabase(database, "password123", null);
secureDB.execSQL("CREATE TABLE IF NOT EXISTS Accounts(Username VARCHAR,Password VARCHAR);");
secureDB.execSQL("INSERT INTO Accounts VALUES('admin','AdminPassEnc');");
secureDB.close();

```

If encrypted SQLite databases are used, check if the password is hardcoded in the source, stored in shared preferences or hidden somewhere else in the code or file system.
A secure approach to retrieve the key, instead of storing it locally could be to either:

- Ask the user every time for a PIN or password to decrypt the database, once the app is opened (weak password or PIN is prone to brute force attacks), or
- Store the key on the server and make it accessible via a web service (then the app can only be used when the device is online).

##### Realm Databases

The [Realm Database for Java](https://realm.io/docs/java/latest/ "Realm Database") is getting more and more popular amongst developers. The database and its content can be encrypted by providing a key in the  configuration.

```java
//the getKey() method either gets the key from the server or from a Keystore, or is deferred from a password.
RealmConfiguration config = new RealmConfiguration.Builder()
  .encryptionKey(getKey())
  .build();

Realm realm = Realm.getInstance(config);

```

If encryption is not used, you should be able to obtain the data. If encryption is enabled, check if the key is hardcoded in the source or resources, whether it is stored unprotected in shared preferences or somewhere else.

##### Internal Storage

Files can be saved directly on the [internal storage](http://developer.android.com/guide/topics/data/data-storage.html#filesInternal "Using Internal Storage") of the device. By default, files saved to the internal storage are private to your app and other apps cannot access them. When the user uninstalls your app, these files are removed.
Within an activity the following code might be used to store sensitive information in the variable `test` persistently to the internal storage:

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

The file mode needs to be checked to make sure that only the app itself has access to the file. This can be set by using `MODE_PRIVATE`. Other modes like `MODE_WORLD_READABLE` (deprecated) and  `MODE_WORLD_WRITEABLE` (deprecated) are more lax and can pose a security risk.

It should also be checked what files are opened and read within the app by searching for the class `FileInputStream`. Part of the internal storage mechanisms is also the cache storage. To cache data temporarily, functions like `getCacheDir()` can be used.

##### External Storage

Every Android-compatible device supports a [shared external storage](https://developer.android.com/guide/topics/data/data-storage.html#filesExternal "Using External Storage") that you can use to save files. This can be a removable storage media (such as an SD card) or an internal (non-removable) storage.
Files saved to the external storage are world-readable and can be modified by the user when they enable USB mass storage to transfer files on a computer.
Within an activity the following code might be used to store sensitive information in the file `password.txt` persistently to the external storage:

```java
File file = new File (Environment.getExternalFilesDir(), "password.txt");
String password = "SecretPassword";
FileOutputStream fos;
    fos = new FileOutputStream(file);
    fos.write(password.getBytes());
    fos.close();
```

Once the activity is called, the file is created with the provided data and the data is stored in clear text in the external storage.

It’s also worth to know that files stored outside the application folder (`data/data/<package-name>/`) will not be deleted when the user uninstalls the application.

#### Static Analysis

##### Local Storage

As already pointed out, there are several ways to store information within Android. Several checks should therefore be applied to the source code to identify the storage mechanisms used within the Android app and whether sensitive data is processed insecurely.

- Check `AndroidManifest.xml` for permissions to read from or write to external storage, like `uses-permission android:name="android.permission.WRITE_EXTERNAL_STORAGE"`
- Check the source code for keywords and API calls that are used for storing data:
    - File permissions like:
      - `MODE_WORLD_READABLE` or `MODE_WORLD_WRITABLE`: Usage of `MODE_WORLD_WRITEABLE` or `MODE_WORLD_READABLE` should generally be avoided for files, as any app would be able to read or write the file even though it may be stored in the app private data directory. If data needs to be shared with other applications, a content provider should be considered. A content provider offers read and write permissions to other apps and can make dynamic permission grants on a case-by-case basis.
    - Classes and functions like:
      - `SharedPreferences` Class (Storage of key-value pairs)
      - `FileOutPutStream` Class (Using Internal or External Storage)
      - `getExternal*` functions (Using External Storage)
      - `getWritableDatabase` function (return a SQLiteDatabase for writing)
      - `getReadableDatabase` function (return a SQLiteDatabase for reading)
      - `getCacheDir` and `getExternalCacheDirs` function (Using cached files)

Encryption operations should rely on solid and tested functions provided by the SDK. The following describes different “bad practices” that should be checked in the source code:

- Check if simple bit operations are used, like XOR or Bit flipping to “encrypt” sensitive information that is stored locally. This should be avoided as the data can easily be recovered.
- Check if keys are created or used without taking advantage of the Android onboard features like the Android KeyStore.
- Check if keys are disclosed by hardcoding them in the source code.

###### Typical Misuse: Hardcoded Cryptographic Keys

The use of a hardcoded or world-readable cryptographic key significantly increases the possibility that encrypted data may be recovered. Once it is obtained by an attacker, the task to decrypt the sensitive data becomes trivial, and the initial idea to protect confidentiality fails. When using symmetric cryptography, the key needs to be stored within the device and it is just a matter of time and effort from the attacker to identify it. Consider the following scenario: An application is reading and writing to an encrypted database but the decryption is done based on a hardcoded key:

```Java
this.db = localUserSecretStore.getWritableDatabase("SuperPassword123");
```

Since the key is the same for all app installations it is trivial to obtain it. The advantages of having sensitive data encrypted are gone, and there is effectively no benefit in using encryption in this way. Similarly, look for hardcoded API keys/private keys and other valuable pieces. Encoded/encrypted keys is just another attempt to make it harder but not impossible to get the crown jewels.

Let's consider this piece of code:

```Java
//A more complicated effort to store the XOR'ed halves of a key (instead of the key itself)
private static final String[] myCompositeKey = new String[]{
  "oNQavjbaNNSgEqoCkT9Em4imeQQ=","3o8eFOX4ri/F8fgHgiy/BS47"
};
```

Algorithm to decode the original key in this case might look like this:

```Java
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

Verify common places where secrets are usually hidden:
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
```
buildTypes {
  debug {
    minifyEnabled true
    buildConfigField "String", "hiddenPassword", "\"${hiddenPassword}\""
  }
}
```

##### KeyStore

The [Android KeyStore](http://www.androidauthority.com/use-android-keystore-store-passwords-sensitive-information-623779/ "Use Android KeyStore") provides a means of (more or less) secure credential storage. As of Android 4.3, it provides public APIs for storing and using app-private keys. An app can create a new private/public key pair to encrypt application secrets by using the public key and decrypt the same by using the private key.

The keys stored in the Android KeyStore can be protected such that the user needs to authenticate to access them. The user's lock screen credentials (pattern, PIN, password or fingerprint) are used for authentication.

Stored keys can be configured to operate in one of the two modes:

1. User authentication authorizes the use of keys for a duration of time. All keys in this mode are authorized for use as soon as the user unlocks the device.  The duration for which the authorization remains valid can be customized for each key. This option can only be used if the secure lock screen is enabled. If the user disables the secure lock screen, any stored keys become permanently invalidated.

2. User authentication authorizes a specific cryptographic operation associated with one key. In this mode, each operation involving such a key must be individually authorized by the user. Currently, the only means of such authorization is fingerprint authentication.

The level of security afforded by the Android KeyStore depends on its implementation, which differs between devices. Most modern devices offer a hardware-backed KeyStore implementation. In that case, keys are generated and used in a Trusted Execution Environment (TEE) or a Secure Element (SE) and are not directly accessible for the operating system. This means that the encryption keys themselves cannot be easily retrieved, even from a rooted device. You can check whether the keys are inside the secure hardware, based on the return value of the `isInsideSecureHardware()` method which is part of the [class `KeyInfo`](https://developer.android.com/reference/android/security/keystore/KeyInfo.html "Class KeyInfo"). Please note that private keys are often indeed stored correctly within the secure hardware, but secret keys, HMAC keys are, are not stored securely according to the KeyInfo on quite some devices.

In a software-only implementation, the keys are encrypted with a [per-user encryption master key](https://nelenkov.blogspot.sg/2013/08/credential-storage-enhancements-android-43.html "Nikolay Elenvok - Credential storage enhancements in Android 4.3"). In that case, an attacker can access all keys on a rooted device in the folder `/data/misc/keystore/`. As the master key is generated using the user’s own lock screen pin/password, the Android KeyStore is unavailable when the device is locked.

##### Older KeyStore Implementations

Older Android versions do not have a KeyStore, but do have the KeyStore interface from JCA (Java Cryptography Architecture). One can use various KeyStores that implement this interface and ensure secrecy and integrity to the keys stored in the KeyStore implementation. All implementations rely on the fact that a file is stored on the filesystem, which then protects its content by a password. For this, it is recommended to use the BouncyCastle KeyStore (BKS).
You can create one by using the `KeyStore.getInstance("BKS", "BC");`, where "BKS" is the KeyStore name (BouncyCastle Keystore) and "BC" is the provider (BouncyCastle). Alternatively you can use SpongyCastle as a wrapper and initialize the KeyStore: `KeyStore.getInstance("BKS", "SC");`.

Please be aware that not all KeyStores offer proper protection to the keys stored in the KeyStore files.

##### KeyChain

The [KeyChain class](http://developer.android.com/reference/android/security/KeyChain.html "Android KeyChain") is used to store and retrieve *system-wide* private keys and their corresponding certificate (chain). The user will be prompted to set a lock screen pin or password to protect the credential storage if it hasn’t been set and if something gets imported into the KeyChain the first time. Please note that the KeyChain is system-wide: so every application can access the materials stored in the KeyChain.

When going through the source code it should be analyzed if native mechanisms that are offered by Android are applied to the identified sensitive information. Sensitive information must not be stored in clear text but should be encrypted. If sensitive information needs to be stored on the device itself, several API calls are available to protect the data on the Android device by using the **KeyChain** class. The following should therefore be done:

- Check that the app is using the Android KeyStore and Cipher mechanisms to securely store encrypted information on the device. Look for the pattern `import java.security.KeyStore`, `import javax.crypto.Cipher`, `import java.security.SecureRandom` and corresponding usages.
- The `store(OutputStream stream, char[] password)` function can be used to store the KeyStore to disk with a specified password. Check that the password provided is not hardcoded and is defined by user input as this should only be known to the user.

#### Dynamic Analysis

Install and use the app as it is intended and execute all functions at least once. Data can be generated when entered by the user, sent by the endpoint or it is already shipped within the app when installing it. Afterwards check the following items:

- Check the files that are shipped with the mobile application once installed in `/data/data/<package-name>/` in order to identify development, backup or simply old files that shouldn’t be in a production release.
- Check if SQLite databases are available and if they contain sensitive information. SQLite databases are stored in `/data/data/<package-name>/databases`.
- Check Shared Preferences that are stored as XML files for sensitive information, which are stored in `/data/data/<package-name>/shared_prefs`. The usage of Shared Preferences or other mechanisms that are not able to protect data should be avoided to store sensitive information. Shared Preferences are insecure and not encrypted by default. [Secure-preferences](https://github.com/scottyab/secure-preferences "Secure-preferences encrypts the values of Shared Preferences") can be used to encrypt the values stored within Shared Preferences, but the Android KeyStore should be the first option to store data securely.
- Check the file system permissions of the files in `/data/data/<package-name>`. Only the user and group created when installing the app (e.g. u0_a82) should have the user rights read, write and execute (`rwx`). Others should have no permissions to files, but may have the executable flag to directories.
- Check if there is a Realm database available in `/data/data/<package-name>/files/` and if it is unencrypted and contains sensitive information. The file extension is `realm` and the file name is `default` by default. Inspecting the Realm database is done with the [Realm Browser](https://github.com/realm/realm-browser-osx "Realm Browser for macOS").
- Check the external storage if any data has been saved there. Do not use the external storage for sensitive data, as it is read and writeable system-wide.

By default, files saved to the internal storage are private to your application and other applications cannot access them (nor can the user). When the user uninstalls your application, these files are also removed.

### Testing for Sensitive Data in Logs

#### Overview

There are many legit reasons to create log files on a mobile device, for example to keep track of crashes or errors or simply for usage statistics. Log files can be stored locally when being offline and being sent to the endpoint once being online again. However, logging sensitive data such as usernames or session IDs might expose the data to attackers or malicious applications and violates the confidentiality of the data.
Log files can be created in different ways and the following list shows two classes that are available on Android:

- [Log Class](https://developer.android.com/reference/android/util/Log.html "Log Class")
- [Logger Class](https://developer.android.com/reference/java/util/logging/Logger.html "Logger Class")

A centralized logging class and mechanism should be used and logging statements should be removed from the production release, as logs may be interrogated or readable by other applications.

#### Static Analysis

The source code should be checked for logging mechanisms used within the Android App, by searching for the following keywords:

1. Functions and classes like:
  * `android.util.Log`
  * `Log.d` | `Log.e` | `Log.i` | `Log.v` | `Log.w` | `Log.wtf`
  * `Logger`

2. Keywords and system output to identify non-standard log mechanisms like:
  * `System.out.print` | `System.err.print`
  * logfile
  * logging
  * logs

Tools like `ProGuard`, which is already included in Android Studio can be used to strip out logging portions in the code when preparing the production release. Verify if all of the logging functions of the class `android.util.Log` are removed by checking the configuration file of ProGuard (_proguard-project.txt_) for the following options:

```java
-assumenosideeffects class android.util.Log
{
  public static boolean isLoggable(java.lang.String, int);
  public static int v(...);
  public static int i(...);
  public static int w(...);
  public static int d(...);
  public static int e(...);
  public static int wtf(...);
}
```

Please note that the above example only ensures that calls to the methods offered by the Log class will be removed. However, if the string to be logged is dynamically constructed, the code for constructing the string might remain in the bytecode. For example, the following code issues an implicit StringBuilder to construct the log statement:

```java
Log.v(TAG, "Private key [byte format]: " + key);
```

The compiled bytecode however, is equivalent to the bytecode of the following log statement, which has the string constructed explicitly:

```java
Log.v(TAG, new StringBuilder("Private key [byte format]: ").append(key.toString()).toString());
```

What ProGuard guarantees is the removal of the `Log.v` method call. Whether the rest of the code (`new StringBuilder ...`) will be removed depends on the complexity of the code and the [ProGuard version used](https://stackoverflow.com/questions/6009078/removing-unused-strings-during-proguard-optimisation "Removing unused strings during ProGuard optimization ").

This is potentially a security risk, as the (now unused) string leaks plain text data in memory which can be accessed over a debugger or by memory dumping.

Unfortunately, there is no silver bullet against this issue, but there are few options available:

- Implement a custom logging facility that takes simple arguments and does the construction of the log statements internally.

```java
SecureLog.v("Private key [byte format]: ", key);
```
Then configure ProGuard to strip its calls.

- Remove logs on source level, instead of compiled bytecode level. Below is a simple Gradle task which comments out all log statements including any inline string builder.

```
afterEvaluate {
    project.getTasks().findAll { task -> task.name.contains("compile") && task.name.contains("Release")}.each { task ->
      task.dependsOn('removeLogs')
}

  task removeLogs() {
    doLast {
      fileTree(dir: project.file('src')).each { File file ->
        def out = file.getText("UTF-8").replaceAll("((android\\.util\\.)*Log\\.([ewidv]|wtf)\\s*\\([\\S\\s]*?\\)\\s*;)", "/*\$1*/")
        file.write(out);
    }
  }
}
```

#### Dynamic Analysis

Use the mobile app extensively so that all functionality is at least triggered once. Afterwards identify the data directory of the application in order to look for log files (`/data/data/<package-name>`). Check if log data is generated by checking the application logs, as some mobile applications create and store their own logs in the data directory.  

Many application developers still use `System.out.println()` or `printStackTrace()` instead of a proper logging class. Therefore, the testing approach also needs to cover all output generated by the application during starting, running and closing of it. In order to verify what data is printed directly by using `System.out.println()` or `printStackTrace()` the tool [`Logcat`](http://developer.android.com/tools/debugging/debugging-log.html "Debugging with Logcat") can be used to check the app output. Two different approaches are available to execute Logcat.

* Logcat is already part of _Dalvik Debug Monitor Server_ (DDMS) and is built into Android Studio. If the app is in debug mode and running, the log output is shown in the Android Monitor in the Logcat tab. Patterns can be defined in Logcat to filter the log output of the app.

![Log output in Android Studio](Images/Chapters/0x05d/log_output_Android_Studio.png)

* Logcat can be executed by using adb in order to store the log output permanently.

```bash
$ adb logcat > logcat.log
```

### Testing Whether Sensitive Data is Sent to Third Parties

#### Overview

Different 3rd party services are available that can be embedded into the app to implement different features. These features can vary from tracker services to monitor the user behavior within the app, selling banner advertisements or to create a better user experience. Interacting with these services abstracts the complexity and neediness to implement the functionality on its own and to reinvent the wheel.

The downside is that a developer doesn’t know in detail what code is executed via 3rd party libraries and therefore giving up visibility. Consequently it should be ensured that not more information as needed is sent to the service and that no sensitive information is disclosed.

3rd party services are mostly implemented in two ways:

- By using a standalone library, like a Jar in an Android project that is getting included into the APK.
- By using a full SDK.

#### Static Analysis

3rd party libraries can be automatically integrated into the app through a wizard within the IDE or by adding a library or SDK manually. In both cases the permissions set in the `AndroidManifest.xml` should be reviewed. Especially permissions to access `SMS (READ_SMS)`, contacts (`READ_CONTACTS`) or the location (`ACCESS_FINE_LOCATION`) should be challenged if they are really needed to make the library work at a bare minimum, see also `Testing App Permissions`. When talking to developers it should be shared to them that it’s actually necessary to have a look at the differences on the project source code before and after the library was added to the project and what changes have been made to the code base.

The source code should be checked for API calls or functions provided by the 3rd party library or SDK. The applied code changes should be reviewed and it should be checked if available security best practices of the library and SDK are applied and used.

The libraries loaded into the project should be reviewed in order to identify with the developers if they are needed and also if they are out of date and contain known vulnerabilities.

All data that is sent to 3rd Party services should be anonymized, so no PII data is available. Also all other data, like IDs in an application that can be mapped to a user account or session should not be sent to a third party.  

#### Dynamic Analysis

All requests made to external services should be analyzed if any sensitive information is embedded into them.
Dynamic analysis can be performed by launching a Man-in-the-middle (MITM) attack using _Burp Suite Professional_ or _OWASP ZAP_, to intercept the traffic exchanged between client and server. Once we are able to route the traffic to the interception proxy, we can try to sniff the traffic from the app to the server and vice versa. When using the app all requests that are not going directly to the server where the main function is hosted should be checked, if any sensitive information is sent to a 3rd party. This could be for example PII (Personal Identifiable Information) in a tracker or ad service.

### Testing Whether the Keyboard Cache Is Disabled for Text Input Fields

#### Overview

When typing in data into input fields, the software keyboard automatically suggests what data the user might want to key in. This feature can be very useful in messaging apps to write text messages more efficiently. For input fields that are asking for sensitive information like credit card data the keyboard cache might disclose sensitive information already when the input field is selected.

#### Static Analysis

In the layout definition of an activity, `TextViews` can be defined that have XML attributes. When the XML attribute `android:inputType` is set with the constant `textNoSuggestions` the keyboard cache is not shown if the input field is selected. Only the keyboard is shown and the user needs to type everything manually and nothing is suggested to him.

```xml
   <EditText
        android:id="@+id/KeyBoardCache"
        android:inputType="textNoSuggestions"/>
```

All input fields that ask for sensitive information, should implement this XML attribute to [disable the keyboard suggestions](https://developer.android.com/reference/android/text/InputType.html#TYPE_TEXT_FLAG_NO_SUGGESTIONS "Disable keyboard suggestions"):

#### Dynamic Analysis

Start the app and click into the input fields that ask for sensitive data. If strings are suggested the keyboard cache is not disabled for this input field.


### Testing for Sensitive Data in the Clipboard

#### Overview

When keying in data into input fields, the [clipboard](https://developer.android.com/guide/topics/text/copy-paste.html "Copy and Paste in Android") can be used to copy data in. The clipboard is accessible system-wide and therefore shared between the apps. This feature can therefore be misused by malicious apps in order to get sensitive data stored in the clipboard.

#### Static Analysis

Input fields that are asking for sensitive information need to be identified and afterwards be investigated if any countermeasures are in place to mitigate the clipboard of showing up. A general best practice is overwriting different functions in the input field to disable the clipboard specifically for it.

```Java
EditText  etxt = (EditText) findViewById(R.id.editText1);
etxt.setCustomSelectionActionModeCallback(new Callback() {

            public boolean onPrepareActionMode(ActionMode mode, Menu menu) {
                return false;
            }

            public void onDestroyActionMode(ActionMode mode) {                  
            }

            public boolean onCreateActionMode(ActionMode mode, Menu menu) {
                return false;
            }

            public boolean onActionItemClicked(ActionMode mode, MenuItem item) {
                return false;
            }
        });
```

Also `longclickable` should be deactivated for the input field.

```xml
android:longClickable="false"
```

#### Dynamic Analysis

Start the app and click into the input fields that ask for sensitive data. When it is possible to get the menu to copy/paste data the functionality is not disabled for this input field.

To extract the data stored in the clipboard, the Drozer module `post.capture.clipboard` can be used:

```
dz> run post.capture.clipboard
[*] Clipboard value: ClipData.Item { T:Secretmessage }
```

### Testing Whether Stored Sensitive Data Is Exposed via IPC Mechanisms

#### Overview

As part of the IPC mechanisms included on Android, content providers allow an app's stored data to be accessed and modified by other apps. If not properly configured, they could lead to leakage of stored sensitive data.

#### Static Analysis

The first step is to look into the `AndroidManifest.xml` in order to detect content providers exposed by the app. Content providers can be identified through the `<provider>` element and the following should be verified:

- Check if the provider has the export tag set to "true" (`android:exported="true"`). Even if this is not the case, remember that if it has an `<intent-filter>` defined, the export tag will be automatically set to "true". Set `android:exported` to "false" if the content is only meant to be accessed by the app itself. If not, set it to "true" and define proper read and write permissions.
- Check if it is being protected by any permission tag (`android:permission`). Permission tags allow to limit the exposure to other apps.
- Check if  the `android:protectionLevel` attribute is set to `signature`, which indicates that it is only intended to be accessed by apps from the same enterprise (signed with the same key). If the intention is to offer access to other apps, a security policy can be applied by using the `<permission>` element and set a proper `android:protectionLevel`. When using `android:permission`, other applications will need to declare a corresponding `<uses-permission>` element in their own manifest to be able to interact with your content provider. More granular access to other apps can be defined by using the `android:grantUriPermissions` attribute in the manifest and the access can be limited with the `<grant-uri-permission>` element.

Inspect the source code to further understand how the content provider is meant to be used. Search for the following keywords:
- `android.content.ContentProvider`
- `android.database.Cursor`
- `android.database.sqlite`
- `.query(`
- `.update(`
- `.delete(`

> In order to avoid SQL injection attacks within the app, use parameterized query methods such as `query()`, `update()`, and `delete()`. Be sure to properly sanitize all inputs to these methods because if, for instance, the `selection` argument is built out of user input concatenation, it could also lead to SQL injection.

When exposing a content provider it should also be checked if parameterized [query methods](https://developer.android.com/reference/android/content/ContentProvider.html#query%28android.net.Uri%2C%20java.lang.String[]%2C%20java.lang.String%2C%20java.lang.String[]%2C%20java.lang.String%29 "Query method in Content Provider Class") (`query()`, `update()`, and `delete()`) are being used to prevent SQL injection. If so, check if all inputs to them are properly sanitized.

As an example of a vulnerable content provider we will use the vulnerable password manager app [Sieve](https://github.com/mwrlabs/drozer/releases/download/2.3.4/sieve.apk "Sieve - Vulnerable Password Manager").

##### Inspect the AndroidManifest
Identify all defined `<provider>` elements:

```xml
<provider android:authorities="com.mwr.example.sieve.DBContentProvider" android:exported="true" android:multiprocess="true" android:name=".DBContentProvider">
    <path-permission android:path="/Keys" android:readPermission="com.mwr.example.sieve.READ_KEYS" android:writePermission="com.mwr.example.sieve.WRITE_KEYS"/>
</provider>
<provider android:authorities="com.mwr.example.sieve.FileBackupProvider" android:exported="true" android:multiprocess="true" android:name=".FileBackupProvider"/>
```

As can be seen in the `AndroidManifest.xml` above, the application exports two content providers. Note that one path ("/Keys") is being protected by read and write permissions.

##### Inspect the source code
In the `DBContentProvider.java` file the `query` function need to be inspected to detect if any sensitive information is leaked:

```java
public Cursor query(final Uri uri, final String[] array, final String s, final String[] array2, final String s2) {
    final int match = this.sUriMatcher.match(uri);
    final SQLiteQueryBuilder sqLiteQueryBuilder = new SQLiteQueryBuilder();
    if (match >= 100 && match < 200) {
        sqLiteQueryBuilder.setTables("Passwords");
    }
    else if (match >= 200) {
        sqLiteQueryBuilder.setTables("Key");
    }
    return sqLiteQueryBuilder.query(this.pwdb.getReadableDatabase(), array, s, array2, (String)null, (String)null, s2);
}
```

Here we see that there are actually two paths, "/Keys" and "/Passwords", being the latter not protected in the manifest and therefore vulnerable.

The query statement would return all passwords when accessing an URI including this path `Passwords/`. We will address this in the dynamic analysis below and find out the exact URI required.


#### Dynamic Analysis

##### Testing Content Providers

To begin dynamic analysis of an application's content providers, you should first enumerate the attack surface. This can be achieved using the Drozer module `app.provider.info` and providing the package name of the app:

```
dz> run app.provider.info -a com.mwr.example.sieve
  Package: com.mwr.example.sieve
  Authority: com.mwr.example.sieve.DBContentProvider
  Read Permission: null
  Write Permission: null
  Content Provider: com.mwr.example.sieve.DBContentProvider
  Multiprocess Allowed: True
  Grant Uri Permissions: False
  Path Permissions:
  Path: /Keys
  Type: PATTERN_LITERAL
  Read Permission: com.mwr.example.sieve.READ_KEYS
  Write Permission: com.mwr.example.sieve.WRITE_KEYS
  Authority: com.mwr.example.sieve.FileBackupProvider
  Read Permission: null
  Write Permission: null
  Content Provider: com.mwr.example.sieve.FileBackupProvider
  Multiprocess Allowed: True
  Grant Uri Permissions: False
```

In the example, two content providers are exported, each not requiring any permission to interact with them, except for the `/Keys` path in the `DBContentProvider`. Using this information you can reconstruct part of the content URIs to access the `DBContentProvider`, because it is known that they must begin with `content://`. However, the full content provider URI is not currently known.

To identify content provider URIs within the application, Drozer's `scanner.provider.finduris` module should be used. This utilizes various techniques to guess paths and determine a list of accessible content URIs:

```
dz> run scanner.provider.finduris -a com.mwr.example.sieve
Scanning com.mwr.example.sieve...
Unable to Query content://com.mwr.example.sieve.DBContentProvider/
...
Unable to Query content://com.mwr.example.sieve.DBContentProvider/Keys
Accessible content URIs:
content://com.mwr.example.sieve.DBContentProvider/Keys/
content://com.mwr.example.sieve.DBContentProvider/Passwords
content://com.mwr.example.sieve.DBContentProvider/Passwords/
```

Now that you have a list of accessible content providers, the next step is to attempt to extract data from each provider, which can be achieved using the `app.provider.query` module:

```
dz> run app.provider.query content://com.mwr.example.sieve.DBContentProvider/Passwords/ --vertical
_id: 1
service: Email
username: incognitoguy50
password: PSFjqXIMVa5NJFudgDuuLVgJYFD+8w== (Base64 - encoded)
email: incognitoguy50@gmail.com
```

In addition to querying data, Drozer can be used to update, insert and delete records from a vulnerable content provider:

- Insert record

```
dz> run app.provider.insert content://com.vulnerable.im/messages
                --string date 1331763850325
                --string type 0
                --integer _id 7
```

- Update record

```
dz> run app.provider.update content://settings/secure
                --selection "name=?"
                --selection-args assisted_gps_enabled
                --integer value 0
```

- Delete record

```
dz> run app.provider.delete content://settings/secure
                --selection "name=?"
                --selection-args my_setting
```

##### SQL Injection in Content Providers

The Android platform promotes the use of SQLite databases for storing user data. Since these databases use SQL, they can be vulnerable to SQL injection. The Drozer module `app.provider.query` can be used to test for SQL injection by manipulating the projection and selection fields that are passed to the content provider:

```
dz> run app.provider.query content://com.mwr.example.sieve.DBContentProvider/Passwords/ --projection "'"
unrecognized token: "' FROM Passwords" (code 1): , while compiling: SELECT ' FROM Passwords

dz> run app.provider.query content://com.mwr.example.sieve.DBContentProvider/Passwords/ --selection "'"
unrecognized token: "')" (code 1): , while compiling: SELECT * FROM Passwords WHERE (')
```

If vulnerable to SQL Injection, the application will return a verbose error message. SQL Injection in Android can be exploited to modify or query data from the vulnerable content provider. In the following example, the Drozer module `app.provider.query` is used to list all tables in the database:

```
dz> run app.provider.query content://com.mwr.example.sieve.DBContentProvider/Passwords/ --projection "*
FROM SQLITE_MASTER WHERE type='table';--"
| type  | name             | tbl_name         | rootpage | sql              |
| table | android_metadata | android_metadata | 3        | CREATE TABLE ... |
| table | Passwords        | Passwords        | 4        | CREATE TABLE ... |
| table | Key              | Key              | 5        | CREATE TABLE ... |
```

SQL Injection can also be exploited to retrieve data from otherwise protected tables:

```
dz> run app.provider.query content://com.mwr.example.sieve.DBContentProvider/Passwords/ --projection "* FROM Key;--"
| Password | pin |
| thisismypassword | 9876 |
```

These steps can be automated by using the `scanner.provider.injection` module, which automatically finds vulnerable content providers within an app:

```
dz> run scanner.provider.injection -a com.mwr.example.sieve
Scanning com.mwr.example.sieve...
Injection in Projection:
  content://com.mwr.example.sieve.DBContentProvider/Keys/
  content://com.mwr.example.sieve.DBContentProvider/Passwords
  content://com.mwr.example.sieve.DBContentProvider/Passwords/
Injection in Selection:
  content://com.mwr.example.sieve.DBContentProvider/Keys/
  content://com.mwr.example.sieve.DBContentProvider/Passwords
  content://com.mwr.example.sieve.DBContentProvider/Passwords/
```

##### File System Based Content Providers

A content provider can provide access to the underlying file system. This allows apps to share files, where the Android sandbox would otherwise prevent it. The Drozer modules `app.provider.read` and `app.provider.download` can be used to read or download files from exported file based content providers. These content providers can be susceptible to directory traversal vulnerabilities, making it possible to read otherwise protected files within the target application's sandbox.

```
dz> run app.provider.download content://com.vulnerable.app.FileProvider/../../../../../../../../data/data/com.vulnerable.app/database.db /home/user/database.db
Written 24488 bytes
```

To automate the process of finding content providers susceptible to directory traversal, the `scanner.provider.traversal` module should be used:

```
dz> run scanner.provider.traversal -a com.mwr.example.sieve
Scanning com.mwr.example.sieve...
Vulnerable Providers:
  content://com.mwr.example.sieve.FileBackupProvider/
  content://com.mwr.example.sieve.FileBackupProvider
```

Note that `adb` can also be used to query content providers on a device:

```bash
$ adb shell content query --uri content://com.owaspomtg.vulnapp.provider.CredentialProvider/credentials
Row: 0 id=1, username=admin, password=StrongPwd
Row: 1 id=2, username=test, password=test
...
```


### Testing for Sensitive Data Disclosure Through the User Interface

#### Overview

In many apps users need to key in different kind of data to for example register an account or execute payment. Sensitive data could be exposed if the app is not masking it properly and showing data in clear text.

Masking of sensitive data within an activity of an app should be enforced to prevent disclosure and mitigate for example shoulder surfing.

#### Static Analysis

To verify if the application is masking sensitive information that is keyed in by the user, check for the following attribute in the definition of EditText:

```
android:inputType="textPassword"
```

This will show dots in the text field instead of the keyed in characters and prevent leaking of passwords or pins in the user interface.

#### Dynamic Analysis

To analyze if the application leaks any sensitive information to the user interface, run the application and identify parts of the app that either shows or asks for such information to be keyed in.

If the information is masked, e.g. by replacing characters in the text field through asterisks or dots the app is not leaking data to the user interface.

### Testing for Sensitive Data in Backups

#### Overview

Like other modern mobile operating systems Android offers auto-backup features. The backups usually include copies of the data and settings of all apps installed on the device. An obvious concern is whether sensitive user data stored by the app might unintentionally leak to those data backups.

Given its diverse ecosystem, Android has a lot of backup options to account for.

- Stock Android has built-in USB backup facilities. A full data backup, or a backup of a particular app's data directory, can be obtained using the `adb backup` command when USB debugging is enabled.

- Google also provides a "Back Up My Data" feature that backs up all app data to Google's servers.

- Two Backup APIs are available to app developers:

  - [Key/Value Backup](https://developer.android.com/guide/topics/data/keyvaluebackup.html "Key/Value Backup") (Backup API or Android Backup Service) uploads selected data to the Android Backup Service.

  - [Auto Backup for Apps](https://developer.android.com/guide/topics/data/autobackup.html "Auto Backup for Apps"): With Android 6.0 (>= API level 23), Google added the "Auto Backup for Apps feature". This feature automatically syncs up to 25MB of app data to the user's Google Drive account.

- OEMs may add additional options. For example, HTC devices have a "HTC Backup" option that, when activated, performs daily backups to the cloud.

#### Static Analysis

##### Local

In order to backup all your application data Android provides an attribute called [`allowBackup`](https://developer.android.com/guide/topics/manifest/application-element.html#allowbackup "allowBackup attribute"). This attribute is set within the `AndroidManifest.xml` file. If the value of this attribute is set to **true**, then the device allows users to backup the application using Android Debug Bridge (ADB) via the command `$ adb backup`.

To prevent backing up the app data, set the `android:allowBackup` attribute to **false** in `AndroidManifest.xml`. If this attribute is not available the allowBackup setting is enabled by default. Therefore it needs to be explicitly set in order to deactivate it.

> Note: If the device was encrypted, then the backup files will be encrypted as well.

Check the `AndroidManifest.xml` file for the following flag:

```xml
android:allowBackup="true"
```

If the value is set to **true**, investigate whether the app saves any kind of sensitive data, check the test case "Testing for Sensitive Data in Local Storage".

##### Cloud

Regardless of using either key/value or auto backup, it needs to be identified:
- what files are sent to the cloud (e.g. SharedPreferences),
- if the files contain sensitive information and
- if sensitive information is protected through encryption before sending it to the cloud.

> Files can also be excluded from [Auto Backup](https://developer.android.com/guide/topics/data/autobackup.html#IncludingFiles "Exclude files from Auto Backup"), in case they should not be shared with the Google Cloud. Sensitive information stored at rest on the device should be encrypted before sending it to the cloud.

- **Auto Backup**: Auto Backup is configured through the boolean attribute `android:allowBackup` within the application's manifest file. If not explicitly set, applications targeting Android 6.0 (API Level 23) or higher enable [Auto Backup](https://developer.android.com/guide/topics/data/autobackup.html#EnablingAutoBackup "Enabling AutoBackup") by default. The attribute `android:fullBackupOnly` can also be used to activate auto backup when implementing a backup agent, but this is only available from Android 6.0 onwards. Other Android versions will be using key/value backup instead.

```xml
android:fullBackupOnly
```

Auto backup includes almost all of the app files and stores them in the Google Drive account of the user, limited to 25MB per app. Only the most recent backup is stored, the previous backup is deleted.

- **Key/Value Backup**: To enable key/value backup the backup agent needs to be defined in the manifest file. Look in `AndroidManifest.xml` for the following attribute:

```xml
android:backupAgent
```

To implement the key/ value backup, either one of the following classes needs to be extended:
- [BackupAgent](https://developer.android.com/reference/android/app/backup/BackupAgent.html "BackupAgent")
-  [BackupAgentHelper](https://developer.android.com/reference/android/app/backup/BackupAgentHelper.html "BackupAgentHelper")

Look for these classes within the source code to check for implementations of key/value backup.


#### Dynamic Analysis

After executing all available functions when using the app, attempt to make a backup using `adb`. If successful, inspect the backup archive for sensitive data. Open a terminal and run the following command:

```bash
$ adb backup -apk -nosystem <package-name>
```

Approve the backup from your device by selecting the _Back up my data_ option. After the backup process is finished, you will have a _.ab_ file in your current working directory.
Run the following command to convert the .ab file into a .tar file.

```bash
$ dd if=mybackup.ab bs=24 skip=1|openssl zlib -d > mybackup.tar
```

Alternatively, use the [_Android Backup Extractor_](https://github.com/nelenkov/android-backup-extractor "Android Backup Extractor") for this task. For the tool to work, you also have to download the Oracle JCE Unlimited Strength Jurisdiction Policy Files for [JRE7](http://www.oracle.com/technetwork/java/javase/downloads/jce-7-download-432124.html "Oracle JCE Unlimited Strength Jurisdiction Policy Files JRE7") or [JRE8](http://www.oracle.com/technetwork/java/javase/downloads/jce8-download-2133166.html "Oracle JCE Unlimited Strength Jurisdiction Policy Files JRE8"), and place them in the JRE lib/security folder. Run the following command to convert the tar file:

```bash
java -jar android-backup-extractor-20160710-bin/abe.jar unpack backup.ab
```

Extract the tar file into your current working directory to perform your analysis for sensitive data.

```bash
$ tar xvf mybackup.tar
```

### Testing for Sensitive Information in Auto-Generated Screenshots

#### Overview

Manufacturers want to provide device users an aesthetically pleasing effect when an application is entered or exited, hence they introduced the concept of saving a screenshot when the application goes into the background. This feature could potentially pose a security risk for an application. Sensitive data could be exposed if a user deliberately takes a screenshot of the application while sensitive data is displayed, or in the case of a malicious application running on the device, that is able to continuously capture the screen. This information is written to local storage, from which it may be recovered either by a rogue application on a rooted device, or by someone who steals the device.

For example, capturing a screenshot of a banking application running on the device may reveal information about the user account, his credit, transactions and so on.

#### Static Analysis

In Android, when the app goes into background a screenshot of the current activity is taken and is used to give a pleasing effect when the app is entered again. However, this would leak sensitive information that is present within the app.

To verify if the application may expose sensitive information via app switcher, detect if the [`FLAG_SECURE`](https://developer.android.com/reference/android/view/Display.html#FLAG_SECURE "FLAG_SECURE Option") option is set. You should be able to find something similar to the following code snippet.

```Java
getWindow().setFlags(WindowManager.LayoutParams.FLAG_SECURE,
                WindowManager.LayoutParams.FLAG_SECURE);

setContentView(R.layout.activity_main);
```

If not, the application is vulnerable to screen capturing.

#### Dynamic Analysis

During black-box testing, open any screen within the app that contains sensitive information and click on the home button so that the app goes into background. Now press the app-switcher button, to see the snapshot. As shown below, if `FLAG_SECURE` is set (image on the right), the snapshot is empty, while if the `FLAG_SECURE` is not set (image on the left), information within the activity is shown:

| `FLAG_SECURE` not set  | `FLAG_SECURE` set  |
|---|---|
| ![OMTG_DATAST_010_1_FLAG_SECURE](Images/Chapters/0x05d/1.png)   |  ![OMTG_DATAST_010_2_FLAG_SECURE](Images/Chapters/0x05d/2.png) |

### Testing for Sensitive Data in Memory

#### Overview

Analyzing memory can help developers to identify root causes of several problems, such as application crashes. However, it can also be used to gain access to sensitive data. This section describes how to check for disclosure of data within the process' memory.

First, you need to identify which sensitive information is stored in memory. Basically, if you have a sensitive asset it's very likely that at some point it is loaded in memory. The objective is to verify that this info is exposed as briefly as possible.

To be able to investigate the memory of an application a memory dump needs to be created first. Alternatively it can be analyzed in real-time, e.g. over a debugger. No matter the approach, this is a very error prone process from a verification point of view, as what you will get in a certain dump is the data left by the functions that were executed. You might miss executing critical scenarios. Additionally, unless you know the footprint of the data you are looking for (either the exact value, or its format), it is quite easy not to identify it during analysis. For example, if the app performs encryption based on a randomly generated symmetric key, unless you get to know the value of the key by other means, it is very unlikely that you will be able to spot it in memory.

Therefore you are better off starting with static analysis.

#### Static Analysis

Before looking into the source code, it is beneficial to check documentation (if available) and identify application components so that you get the big picture of where certain data might be exposed. For example, sensitive data received from a backend does not only exist in the final model object, but also might have multiple copies in the HTTP client, the XML parser, etc. Ideally you want all of these copies to be removed from memory as soon as possible.

Additionally, understanding application's architecture and its role in the overall system will help you identify sensitive information that does not have to be exposed in memory at all. For example, assume your app receives some data from one server and transfers it to another without the need of any additional computation over it. Then that data can be received and handled encrypted, which prevents exposure in memory.

However, if sensitive data does need to be exposed in memory, then you should make sure your app is designed in a way that exposes this data as briefly as possible, with as fewer copies as possible. In other words, you want a centralized handling of sensitive data (as few components as possible), based on primitive and mutable data structures.

The reason for the later requirement is that it enables developers direct access to memory. You should verify that this access is then used to overwrite the sensitive data with dummy data (typically with zeroes). Examples of preferable data types would include `byte []` or `char []`, but not `String` or `BigInteger`. Whenever you try to modify an immutable object like `String` you actually create a copy and apply the change on it.

Usage of non-primitive mutable types, like `StringBuffer` or `StringBuilder` might be acceptable, but it's indicative and requires closer examination. Namely, `StringBuffer` and similar are used in situations when you have a content that you want to modify (which is what we want). But in order to access it's value, one would typically use the `toString()` method which would create an immutable copy of the data. There are few ways in which you can use these data types such that no immutable copy is made, but the effort to do that is greater than simply using a primitive array. One benefit that you get when using `StringBuffer` and similar is the safe memory management that such data types provide, but this can be a two-edged sword. If you try to modify their content and the new one exceeds the buffer capacity, the buffer will automatically be extended. To do so, the content of the buffer might be copied to a different location, leaving the existing content behind without any reference you can use to overwrite it.

Unfortunately, not many libraries and frameworks are designed to allow overwriting of sensitive data. For example, destroying a key as shown below, does not really removes the key from memory:

```java
SecretKey secretKey = new SecretKeySpec("key".getBytes(), "AES");
secretKey.destroy();
```

Neither does overwriting the backing byte-array from `secretKey.getEncoded()` as the SecretKeySpec based key returns a copy of the backing byte-array. Take a look below in the remediation section below on how to properly remove a `SecretKey` from memory.

Next, RSA key pair is based on `BigInteger` and therefore reside in memory after first use outside of the `AndroidKeyStore`. And some ciphers (such as the AES `Cipher` in `BouncyCastle`) does not properly clean up their byte-arrays.

One other case, where you would typically find sensitive information exposed in memory, is user-provided data (credentials, social security numbers, credit card info, etc.). Regardless of whether you flag the `EditText` as a password field or not, it uses the same mechanism for delivering the content to the app - over the `Editable` interface. If your app does not provide an `Editable.Factory` in order for the `EditText` to instantiate your own `Editable` implementation, then it's very likely that the data provided by the user is exposed in memory longer than necessary. Default `Editable` implementation, the `SpannableStringBuilder`, suffers from the same issues as regular Java `StringBuilder` or `StringBuffer`, discussed above.

To summarize, when performing static analysis for sensitive data exposed in memory, you should:

- Try to identify application components and make a map of where certain data is used.
- Verify that sensitive data is handled in as few components as possible.
- Verify that object references are properly removed, once the object containing sensitive data is no longer needed.
- Preferably, verify garbage collection is requested upon removing references.
- For highly sensitive information, verify data is overwritten as soon as it is no longer needed.
  - Such data must not be passed over immutable data types such as `String` or `BigInteger`.
  - Non-primitive data types, such as `StringBuilder` are indicative and should be avoided.
  - Overwriting should be done before removing references, and outside of the `finalize()` method.
  - Pay attention to third-party components (libraries and frameworks).
    Good indicator is their public API. Is the sensitive data passing the public API handled as proposed in this chapter ?


**The following section describes pitfalls and best practices to avoid leakage of data in memory**

No immutable structures should be used to carry secrets (e.g. `String`, `BigInteger`). Nullifying them will not be effective: the garbage collector might collect them, but they might remain in the heap for a longer period. Nevertheless, you should try to ask for garbage collection after every critical operation (encryption, parsing server response containing sensitive information, etc.). In case some copies of the information are not properly cleaned (explained below) this will help to reduce the time these copies are available in memory.

In order to properly clean sensitive information from memory, best practice is to use primitive data types such as byte-arrays (`byte[]`) or char-arrays (`char[]`) for storing the information. As described in the _Static Analyzes_ section above, usage of mutable non-primitive data types, such as `StringBuffer`, should be avoided.

Make sure to overwrite the content of the critical object once it is no longer needed. One simple and very popular way is to overwrite the content with zeroes:

```java
byte[] secret = null;
try{
    //get or generate the secret, do work with it, make sure you make no local copies
} finally {
    if (null != secret) {
        Arrays.fill(secret, (byte) 0);
    }
}
```
This however, does not truly guarantee that the content will be overwritten in run time. In order to optimize the byte code, the compiler will do analysis in which it can decide not to execute the overwriting of data, as it is no longer used afterwards (unnecessary operation). Even if you verify that the code is present in the compiled DEX, the optimization can still happen during just-in-time or ahead-of-time compilation in the VM.

There is no silver bullet against this problem, as different solutions have different consequences. For example, one may choose to perform some additional calculation (e.g. XOR the data into some other dummy buffer), but there is no guarantee on how deep will the compiler perform it's optimization analysis. On the other hand, using the overwritten data outside of compiler's scope (e.g. serializing it in a temp file) guarantees the overwriting to be performed, but has obvious performance and maintenance impact.

Then, using `Arrays.fill()` method to overwrite the data is a bad practice, as it is an obvious target to be hooked (see _Tampering and Reverse Engineering on Android_ chapter for more details).

Finally, one additional issue with the example above is that the content is overwritten with all zeroes. If the case allows, one should try to overwrite critical objects with random data, or ideally content from other non-critical objects. This will make really hard to construct scanners that can identify sensitive data based on the way such data is managed.

Below is an improved version of the previous example:

```java
byte[] nonSecret = somePublicString.getBytes("ISO-8859-1");
byte[] secret = null;
try{
    //get or generate the secret, do work with it, make sure you make no local copies
} finally {
    if (null != secret) {
        for (int i = 0; i < secret.length; i++) {
            secret[i] = nonSecret[i % nonSecret.length];
        }

        FileOutputStream out = new FileOutputStream("/dev/null");
        out.write(secret);
        out.flush();
        out.close();
    }
}
```

For some additional info on the topic take a look at [Securely Storing Sensitive Data in RAM.](https://www.nowsecure.com/resources/secure-mobile-development/coding-practices/securely-store-sensitive-data-in-ram/ "Securely store sensitive data in RAM")

In the _Static Analysis_ section above, we have also mentioned the issue of properly handling cryptographic keys when using `AndroidKeyStore` or `SecretKey`.

For a better implementation of `SecretKey` please check the `SecureSecretKey` class below. The implementation is probably missing some boilerplate code to make this class compatible with `SecretKey`, but addresses the main security concerns:
- No cross-context handling of sensitive data. Each copy of the key can be cleared within the scope where it was created.
- Local copy is cleared according to the recommendations given above.

```java
public class SecureSecretKey implements javax.crypto.SecretKey, Destroyable {
    private byte[] key;
    private final String algorithm;

    /** Constructs SecureSecretKey instance out of a copy of the provided key bytes.
      * The caller is responsible of clearing the key array provided as input.
      * The internal copy of the key can be cleared by calling the destroy() method.
      */
    public SecureSecretKey(final byte[] key, final String algorithm) {
        this.key = key.clone();
        this.algorithm = algorithm;
    }

    public String getAlgorithm() {
        return this.algorithm;
    }

    public String getFormat() {
        return "RAW";
    }

    /** Returns a copy of the key.
      * Make sure to clear the returned byte array when no longer needed.
      */
    public byte[] getEncoded() {
        if(null == key){
            throw new NullPointerException();
        }

        return key.clone();
    }

    /** Overwrites the key with dummy data to ensure this copy is no longer present in memory.*/
    public void destroy() {
        if (isDestroyed()) {
            return;
        }

        byte[] nonSecret = new String("RuntimeException").getBytes("ISO-8859-1");
        for (int i = 0; i < key.length; i++) {
          key[i] = nonSecret[i % nonSecret.length];
        }

        FileOutputStream out = new FileOutputStream("/dev/null");
        out.write(key);
        out.flush();
        out.close();

        this.key = null;
        System.gc();
    }

    public boolean isDestroyed() {
        return key == null;
    }
}

```

Last case where you would typically find secure information in memory, mentioned in the _Static Analysis_ section, is secure data provided by the user. Often this case is handled by implementing a custom input method, in which case you should follow the recommendations given so far. However, _Android_ allows for information to be partially erased from `EditText` buffers by providing a custom `Editable.Factory`.

```java
EditText editText = ...; //  point your variable to your EditText instance
EditText.setEditableFactory(new Editable.Factory() {
  public Editable newEditable(CharSequence source) {
  ... // return a new instance of a secure implementation of Editable.
  }
});
```

Refer to the `SecureSecretKey` example above for some inspiration on how to implement your `Editable`. Also note that by providing your factory, you are only able to handle securely all copies made by `editText.getText()`. You can also try to overwrite the internal `EditText` buffer by calling `editText.setText()`, but there is no guarantee that the buffer has not been copied before. Also by choosing to relay on the default input method and `EditText` you have no control over the keyboard being used, etc. Therefore use this approach only for semi-confidential information.

#### Dynamic Analysis

Static analysis will help you identify potential problems, but it can not provide you with statistics on how long certain data is exposed in memory, nor it can help you identify problems in closed-source dependencies. This is where dynamic analysis comes into play.

There are basically two ways to analyze the memory of a process: live analysis over a debugger or by analyzing one or more memory dumps. As the first approach is more of a general debugging issue, we concentrate on the second one here.

For rudimentary analysis you can use the built-in tools of Android Studio. They are included under the _Android Monitor_ tab. To make a memory dump, select the device and app you want to analyze and click on _Dump Java Heap_. This will create a _.hprof_ file in the _captures_ directory relative to the project path of the app.

![Create Heap Dump](Images/Chapters/0x05d/Dump_Java_Heap.png)

To navigate trough class instances saved in the memory dump, select the Package Tree View in the tab showing the _.hprof_ file.

![Create Heap Dump](Images/Chapters/0x05d/Package_Tree_View.png)

For more advanced analysis over the memory dump, Eclipse Memory Analyzer (MAT) can be used. It is available either as an Eclipse plugin or as a standalone application.

In order to be able to analyze the dump in MAT you need to use the _hprof-conv_ platform tool, provided with the Android SDK.

```bash
./hprof-conv memory.hprof memory-mat.hprof
```

MAT provides several different tools you can use to analyze the memory dump. For example, you can use the _Histogram_ to get an idea on how many objects have been captured from a certain type, or the _Thread Overview_ to see process' threads and their stack frames. Check the _Dominator Tree_ to learn about keep-alive dependencies between objects. You can use regular expressions to filter out the results in all of these tools.

_Object Query Language_ studio is a MAT tool that enables you to use an SQL-like language for querying objects from the memory dump. It supports simple object transformation trough invocation of Java methods on the particular object, as well as API to build sophisticated tools on top of MAT.

```sql
SELECT * FROM java.lang.String
```
The example above will select all `String` objects present in the memory dump. The results will show the class, memory address, value as well as retain count for the object. To filter out all these info and only see the value of each string, you can do:

```sql
SELECT toString(object) FROM java.lang.String object
```

Or

```sql
SELECT object.toString() FROM java.lang.String object
```

OQL supports primitive data types as well, so to get the content of all `char` arrays you can do something like:

```sql
SELECT toString(arr) FROM char[] arr
```

Don't be surprised if you get similar results as before as, after all, `String` and other Java data types are just wrappers around the primitive ones. Now let's filter out some results. The following example will select all byte arrays which contain the ASN.1 OID of a RSA key. Now, this doesn't necessarily means that the byte array actually contains a RSA key in it, as it might happen that same sequence of bytes are part of something else, but the chances are pretty high.

```sql
SELECT * FROM byte[] b WHERE toString(b).matches(".*1\.2\.840\.113549\.1\.1\.1.*")
```

Finally, you don't have to always select whole objects. If we make an analogy to SQL, then classes would be the tables, objects would be the rows and fields would be the columns. So, if you like to find all objects that have field named "password", you can do something like:

```sql
SELECT password FROM ".*" WHERE (null != password)
```

During your analysis try to search for:
- Indicative field names like: "password", "pass", "pin", "secret", "private", etc.
- Indicative patterns (e.g. RSA footprints) in strings, char arrays, byte arrays, etc.
- Presence of known secrets (e.g. credit card number that you have entered, or authentication token provided by the backend).
- etc.

Obtaining multiple memory dumps and repeating the testing several times will help you draw some statistics on how long certain asset is exposed. Further, observing how one particular memory segment (e.g. byte array) changes over time may lead you to some, otherwise unrecognizable, sensitive data (more on this in the _Remediation_ section below).

### Testing the Device-Access-Security Policy

#### Overview

Apps that are processing or querying sensitive information should ensure that they are running in a trusted and secured environment. In order to be able to achieve this, the app can enforce the following local checks on the device:

- PIN or password set to unlock the device
- Usage of a minimum Android OS version
- Detection of activated USB Debugging
- Detection of encrypted device
- Detection of rooted device (see also "Testing Root Detection")

#### Static Analysis

In order to be able to test the device-access-security policy that is enforced by the app, a written copy of the policy needs to be provided. The policy should define what checks are available and how they are enforced. For example one check could require that the app only runs on Android Marshmallow (Android 6.0) or higher and the app is closing itself or showing a warning if the app is running on an Android version < 6.0.

The functions within the code that implement the policy need to be identified and checked if they can be bypassed.

Different checks on the Android device can be implemented by querying different system preferences from [_Settings.Secure_](https://developer.android.com/reference/android/provider/Settings.Secure.html "Settings.Secure"). The [_Device Administration API_](https://developer.android.com/guide/topics/admin/device-admin.html "Device Administration API") offers different mechanisms to create security aware applications, that are able to enforce password policies or encryption of the device.

#### Dynamic Analysis

The dynamic analysis depends on the checks that are enforced by app and their expected behavior and need to be validated if they can be bypassed.

### References

#### OWASP Mobile Top 10 2016

- M1 - Improper Platform Usage - https://www.owasp.org/index.php/Mobile_Top_10_2016-M1-Improper_Platform_Usage
- M2 - Insecure Data Storage - https://www.owasp.org/index.php/Mobile_Top_10_2016-M2-Insecure_Data_Storage
- M4 - Unintended Data Leakage

#### OWASP MASVS

- V2.1: "System credential storage facilities are used appropriately to store sensitive data, such as user credentials or cryptographic keys."
- V2.2: "No sensitive data is written to application logs."
- V2.3: "No sensitive data is shared with third parties unless it is a necessary part of the architecture."
- V2.4: "The keyboard cache is disabled on text inputs that process sensitive data."
- V2.5: "The clipboard is deactivated on text fields that may contain sensitive data."
- V2.6: "No sensitive data is exposed via IPC mechanisms."
- V2.7: "No sensitive data, such as passwords or pins, is exposed through the user interface."
- V2.8: "No sensitive data is included in backups generated by the mobile operating system."
- V2.9: "The app removes sensitive data from views when backgrounded."
- V2.10: "The app does not hold sensitive data in memory longer than necessary, and memory is cleared explicitly after use."

#### CWE

- CWE-117: Improper Output Neutralization for Logs
- CWE-200 - Information Exposure
- CWE-316 - Cleartext Storage of Sensitive Information in Memory
- CWE-359 - Exposure of Private Information ('Privacy Violation')
- CWE-524 - Information Exposure Through Caching
- CWE-532: Information Exposure Through Log Files
- CWE-534: Information Exposure Through Debug Log Files
- CWE-311 - Missing Encryption of Sensitive Data
- CWE-312 - Cleartext Storage of Sensitive Information
- CWE-522 - Insufficiently Protected Credentials
- CWE-530 - Exposure of Backup File to an Unauthorized Control Sphere
- CWE-634 - Weaknesses that Affect System Processes
- CWE-922 - Insecure Storage of Sensitive Information

#### Tools

- Sqlite3 - http://www.sqlite.org/cli.html
- Realm Browser - Realm Browser - https://github.com/realm/realm-browser-osx
- ProGuard - http://proguard.sourceforge.net/
- Logcat - http://developer.android.com/tools/help/logcat.html
- Burp Suite Professional - https://portswigger.net/burp/
- OWASP ZAP - https://www.owasp.org/index.php/OWASP_Zed_Attack_Proxy_Project
- Drozer - https://labs.mwrinfosecurity.com/tools/drozer/
- Android Backup Extractor - https://github.com/nelenkov/android-backup-extractor
- Memory Monitor - http://developer.android.com/tools/debugging/debugging-memory.html#ViewHeap
- Eclipse’s MAT (Memory Analyzer Tool) standalone - https://eclipse.org/mat/downloads.php
- Memory Analyzer which is part of Eclipse - https://www.eclipse.org/downloads/
- Fridump - https://github.com/Nightbringer21/fridump
- LiME - https://github.com/504ensicsLabs/LiME
