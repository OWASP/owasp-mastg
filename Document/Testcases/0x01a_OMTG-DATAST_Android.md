## Android


### <a name="OMTG-DATAST-001"></a>OMTG-DATAST-001: Test for Sensitive Data in Local Storage

#### Overview

[Storing data][fb530e1c] is essential for many mobile applications, for example in order to keep track of user settings or data a user might has keyed in that needs to stored locally or offline. Data can be stored persistently in various ways. The following table shows those mechanisms that are available on the Android platform:

* Shared Preferences
* Internal Storage  
* External Storage  
* SQLite Databases  

The following examples shows snippets of code to demonstrate bad practices that discloses sensitive information and also shows the different mechanisms in Android to store data.

##### Shared Preferences

[SharedPreferences][afd8258f] is a common approach to store Key/Value pairs persistently in the filesystem by using a XML structure. Within an Activity the following code might be used to store sensitive information like a username and a password:

```java
SharedPreferences sharedPref = getSharedPreferences("key", MODE_WORLD_READABLE);
SharedPreferences.Editor editor = sharedPref.edit();
editor.putString("username", "administrator");
editor.putString("password", "supersecret");
editor.commit();
```

Once the activity is called, the file key.xml is created with the provided data. This code is violating several best practices.

* The username and password is stored in clear text in `/data/data/<PackageName>/shared_prefs/key.xml`

```xml
<?xml version='1.0' encoding='utf-8' standalone='yes' ?>
<map>
  <string name="username">administrator</string>
  <string name="password">supersecret</string>
</map>
```

* `MODE_WORLD_READABLE` allows all applications to access and read the content of `key.xml`

```bash
root@hermes:/data/data/sg.vp.owasp_mobile.myfirstapp/shared_prefs # ls -la
-rw-rw-r-- u0_a118 u0_a118    170 2016-04-23 16:51 key.xml
```

> Please note that `MODE_WORLD_READABLE` and `MODE_WORLD_WRITEABLE` were deprecated in API 17. Although this may not affect newer devices, applications compiled with android:targetSdkVersion set prior to 17 may still be affected, if they run on OS prior to Android 4.2 (`JELLY_BEAN_MR1`).


##### SQLite Database (Unencrypted)

SQLite is a SQL database that stores data to a .db file. The Android SDK comes with built in classes to operate SQLite databases. The main package to manage the databases is android.database.sqlite.
Within an Activity the following code might be used to store sensitive information like a username and a password:

```java
SQLiteDatabase notSoSecure = openOrCreateDatabase("privateNotSoSecure",MODE_PRIVATE,null);
notSoSecure.execSQL("CREATE TABLE IF NOT EXISTS Accounts(Username VARCHAR,Password VARCHAR);");
notSoSecure.execSQL("INSERT INTO Accounts VALUES('admin','AdminPass');");
notSoSecure.close();
```

Once the activity is called, the database file `privateNotSoSecure` is created with the provided data and the data is stored in clear text in `/data/data/<PackageName>/databases/privateNotSoSecure`.

There might be several files available in the databases directory, besides the SQLite database.

* Journal files: These are temporary files used to implement atomic commit and rollback capabilities in SQLite (see also [tempfiles] ).
* Lock files: The lock files are part of the locking and journaling mechanism designed to improve concurrency in SQLite and to reduce the writer starvation problem. You can read more here: [lockingv3].

Unencrypted SQLite databases should not be used to store sensitive information.

##### SQLite Databases (Encrypted)

By using the library [SQLCipher][7e90d2dc] SQLite databases can be encrypted, by providing a password.

```java
SQLiteDatabase secureDB = SQLiteDatabase.openOrCreateDatabase(database, "password123", null);
secureDB.execSQL("CREATE TABLE IF NOT EXISTS Accounts(Username VARCHAR,Password VARCHAR);");
secureDB.execSQL("INSERT INTO Accounts VALUES('admin','AdminPassEnc');");
secureDB.close();

```

If encrypted SQLite databases are used, check if the password is hardcoded in the source, stored in shared preferences or hidden somewhere else in the code or file system.
A secure approach to retrieve the key, instead of storing it locally could be to either:

* Ask the user every time for a PIN or password to decrypt the database, once the App is opened (weak password or PIN is prone to Brute Force Attacks), or
* Store the key on the server and make it accessible via a Web Service (then the App can only be used when the device is online)

##### Internal Storage

Files can be saved directly on the device's [internal storage][e65ea363]. By default, files saved to the internal storage are private to your application and other applications cannot access them (nor can the user). When the user uninstalls your application, these files are removed.
Within an Activity the following code might be used to store sensitive information in the variable test persistently to the internal storage:

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

The file mode need to be checked, to make sure that only the app itself has access to the file by using `MODE_PRIVATE`. Other modes like `MODE_WORLD_READABLE` (deprecated) and  `MODE_WORLD_WRITEABLE` (deprecated) are more lax and can pose a security risk.

It should also be checked what files are read within the App by searching for the usage of class `FileInputStream`. Part of the internal storage mechanisms is also the cache storage. To cache data temporarily, functions like `getCacheDir()` can be used.

##### External Storage

Every Android-compatible device supports a shared "[external storage][5e4c3059]" that you can use to save files. This can be a removable storage media (such as an SD card) or an internal (non-removable) storage.
Files saved to the external storage are world-readable and can be modified by the user when they enable USB mass storage to transfer files on a computer.
Within an Activity the following code might be used to store sensitive information in the variable password persistently to the external storage:

```java
File file = new File (Environment.getExternalFilesDir(), "password.txt");
String password = "SecretPassword";
FileOutputStream fos;
    fos = new FileOutputStream(file);
    fos.write(password.getBytes());
    fos.close();
```

Once the activity is called, the file is created with the provided data and the data is stored in clear text in the external storage.

It’s also worth to know that files stored outside the application folder (internal: `data/data/com.appname/files` or external: `/storage/emulated/0/Android/data/com.appname/files/`) will not be deleted when the user uninstall the application.

##### KeyChain and KeyStore

Mobile operating systems offer different native functions to store sensitive information like credentials and keys encrypted within the device. In case keys or other sensitive information needs to be stored, several best practices available on the OS level should be applied to make it harder for attackers to retrieve these information. The following tasks should be done when analysing an App:

* Identify keys and passwords in the App, e.g. entered by the users, sent by the endpoint, shipped within the App and how this sensitive data is processed locally.
* Decide with the developers if this sensitive stored information locally is needed and if not, how it can be moved to the endpoint or completely deleted.

The credo for saving data can be summarized quite easy: Public data should be available for everybody, but sensitive and private data needs to be protected or not stored in the first place on the device itself.

This vulnerability occurs when sensitive data is not properly protected by an app when persistently storing it. The App might be able to store it in different places, for example locally on the device or on an external SD card. When trying to exploit this kind of issues, consider that there might be a lot of information processed and stored in different locations. It is important to identify at the beginning what kind of information is processed by the mobile application and keyed in by the user and what might be interesting and valuable for an attacker (e.g. passwords, credit card information).

This vulnerability can have many consequences, like disclosure of encryption keys that can be used by an attacker to decrypt information. More generally speaking an attacker might be able to identify these information to use it as a basis for other attacks like social engineering (when PII is disclosed), session hijacking (if session information or a token is disclosed) or gather information from Apps that have a payment option in order to attack and abuse it.


#### White-box Testing

##### Local Storage

As already pointed out, there are several ways to store information within Android. Several checks should therefore be applied to the source code to identify the storage mechanisms used within the Android App and if sensitive data is processed insecurely.

* Check `AndroidManifest.xml` for permissions to read and write to external storage, like `uses-permission android:name="android.permission.WRITE_EXTERNAL_STORAGE"`
* Check the source code for functions and API calls that are used for storing data:
  * Open the Java Files in an IDE or text editor of your choice or use grep on the command line to search for:
    * file permissions like:
      * `MODE_WORLD_READABLE` or `MODE_WORLD_WRITABLE`. IPC files should not be created with permissions of `MODE_WORLD_READABLE` or `MODE_WORLD_WRITABLE` unless it is required as any app would be able to read or write the file even though it may be stored in the app’s private data directory.
    * Classes and functions like:
      * `SharedPreferences` Class (Storage of key-value pairs)
      * `FileOutPutStream` Class (Using Internal or External Storage)
      * `getExternal*` functions (Using External Storage)
      * `getWritableDatabase` function (return a SQLiteDatabase for writing)
      * `getReadableDatabase` function (return a SQLiteDatabase for reading)
      * `getCacheDir` and `getExternalCacheDirs` function (Using cached files)

##### KeyChain and KeyStore

Encryption operations should rely on solid and tested functions provided by the SDK. The following describes different “bad practices” that should be checked with the source code:

* Check if simple bit operations are used, like XOR or Bit flipping to “encrypt” sensitive information like credentials or private keys that are stored locally. This should be avoided as the data can easily be recovered.
* Check if keys are created or used without taking advantage of the Android onboard features like the [KeyStore][19149717].
* Identify what kind of information is stored persistently and if credentials or keys are disclosed.

When going through the source code it should be analyzed if native mechanisms that are offered by Android are applied to the identified sensitive information. Sensitive information should not be stored in clear text and should be encrypted. If sensitive information needs to be stored on the device itself, several functions/API calls are available to protect the data on the Android device by using the **KeyChain** and **Keystore**. The following controls should therefore be used:

* Check if a key pair is created within the App by looking for the class `KeyPairGenerator`.
* Check that the application is using the KeyStore and Cipher mechanisms to securely store encrypted information on the device. Look for the pattern `import java.security.KeyStore`, `import javax.crypto.Cipher`, `import java.security.SecureRandom` and it’s usage.
* The `store(OutputStream stream, char[] password)` function can be used to store the KeyStore to disk with a specified password. Check that the password provided is not hardcoded and is defined by user input as this should only be known to the user. Look for the pattern `.store(`.

The code should also be analysed if sensitive data is used properly and securely:

* Sensitive information should not be stored for too long in the RAM (see also [OMTG-DATAST-011 - Testing for Sensitive Data Disclosure in Process Memory](#OMTG-DATAST-011)).
* Set variables that use sensitive information to null once finished.
* Use immutable objects for sensitive data so it cannot be changed.


#### Black-box Testing

Install and use the App as it is intended and execute all functions at least once. Afterwards check the following items:

* Check the files that are shipped with the mobile application once installed in /data/data/<AppName>/files in order to identify development, backup or simply old files that shouldn’t be in a production release.
* Check if .db files are available, which are SQLite databases and if they contain sensitive information (usernames, passwords, keys etc.). SQLite databases are stored in /data/data/<AppName>/databases.
* Check Shared Preferences that are stored as XML files in the shared_prefs directory of the App for sensitive information.
* Check the file system permissions of the files in /data/data/<app name>. The permission should only allow **rwx** to the user and his group that was created for the app (e.g. u0_a82) but not to others. Others should have no permissions to files, but may have the executable flag to directories.

##### KeyChain and KeyStore

When targeting Android applications, the best way to proceed is to first decompile them in order to obtain something close to the source code (_**see Decompiling Android App Guide - #TODO-Create a general guide that can bee referenced anywhere in the OMSTF**_). With the code in your hands you should then be able to inspect and verify if system credentials storage facilities are in place.

#### Remediation

If sensitive information (credentials, keys, PII, etc.) is needed locally on the device several best practices are offered by Android that should be used to store data securely instead of reinventing the wheel or leave it unencrypted on the device.

The following is a list of best practice used for secure storage of certificates and keys and sensitive data in general:

* [Android KeyStore][19149717]: The KeyStore provides a secure system level credential storage. It is important to note that the credentials are not actually stored within the KeyStore. An app can create a new private/public key pair to encrypt application secrets by using the public key and decrypt the same by using the private key. The KeyStores is a secure container that makes it difficult for an attacker to retrieve the private key and guards the encrypted data. Nevertheless an attacker can access all keys on a rooted device in the folder `/data/misc/keystore/`. The KeyStore is encrypted using the user’s own lockscreen pin/password, hence, when the device screen is locked the KeyStore is unavailable. More information can be found here: [how to use Android Keystore][0d4e8f69].
* [Android KeyChain][707361af]: The KeyChain class is used to store and retrieve private keys and their corresponding certificate (chain). The user will be prompted to set a lock screen PIN or password to protect the credential storage if it hasn’t been set, if something gets imported into the KeyChain the first time.
* Encryption or decryption functions that were self implemented need to be avoided. Instead use Android implementations such as [Cipher][8705d59b], [SecureRandom][c941abfc] and [KeyGenerator][fcc82125].   
* Username and password should not be stored on the device. Instead, perform initial authentication using the username and password supplied by the user, and then use a short-lived, service-specific authorization token (session token). If possible, use the [AccountManager][ff4a4029] class to invoke a cloud-based service and do not store passwords on the device.
* As a security in depth measure code obfuscation should also be applied to the App, to make reverse engineering harder for attackers.
* Usage of `MODE_WORLD_WRITEABLE` or `MODE_WORLD_READABLE` should generally be avoided for files. If data needs to be shared with other applications, a content provider should be considered. A content provider offers read and write permissions to other apps and can make dynamic permission grants on a case-by-case basis.
* The usage of Shared Preferences or other mechanisms that are not able to protect data should be avoided to store sensitive information. SharedPreferences are insecure and not encrypted by default. [“Secure-preferences][6dea1401]” can be used to encrypt the values stored within [Shared Preferences][afd8258f].
* Do not use the external storage for sensitive data. By default, files saved to the internal storage are private to your application and other applications cannot access them (nor can the user). When the user uninstalls your application, these files are removed.
* To provide additional protection for sensitive data, you might choose to encrypt local files using a key that is not directly accessible to the application. For example, a key can be placed in a [KeyStore][19149717] and protected with a user password that is not stored on the device. While this does not protect data from a root compromise that can monitor the user inputting the password, it can provide protection for a lost device without file system encryption.


#### References

* [How to use the Android Keystore to store passwords and other sensitive information][0d4e8f69]
* [Android KeyChain][707361af]
* [Android KeyStore][19149717]

##### OWASP MASVS

- V2.1: "System credential storage facilities are used appropriately to store sensitive data, such as user credentials or cryptographic keys."

##### OWASP Mobile Top 10
* M1 - Improper Platform Usage
* M2 - Insecure Data Storage

##### CWE
* CWE-311 - Missing Encryption of Sensitive Data
* CWE-312 - Cleartext Storage of Sensitive Information
* CWE-522 - Insufficiently Protected Credentials
* CWE-922 - Insecure Storage of Sensitive Information

##### Info

* [Internal Storage][e65ea363]
* [External Storage][5e4c3059]
* [Storing Data][fb530e1c]
* [Shared Preferences][afd8258f]
* [SQLCipher][7e90d2dc]
* [SecurePreferences][6dea1401]
* [Android Keystore][19149717]
* [Android Storage Documentation][1e23894b]

##### Tools
* [Enjarify][be9ea354]
* [JADX][b54750a7]
* [Dex2jar][3d1bb980]
* [Lint][a9965341]
* [SQLite3][3b9b0b6f]


### <a name="OMTG-DATAST-002"></a>OMTG-DATAST-002: Test for Sensitive Data in Logs

#### Overview

There are many legit reasons to create log files on a mobile device, for example to keep track of crashes or errors that are stored locally when being offline and being sent to the application developer/company once online again or for usage statistics. However, logging sensitive data such as credit card number and session IDs might expose the data to attackers or malicious applications.
Log files can be created in various ways on each of the different operating systems. The following list shows the mechanisms that are available on Android:

* Log Class, .log[a-Z]
* Logger Class        
* StrictMode  
* System.out/System.err.print

Classification of sensitive information can vary between different industries, countries and their laws and regulations. Therefore laws and regulations need to be known that are applicable to it and to be aware of what sensitive information actually is in the context of the App.

#### White-box Testing

Check the source code for usage of Logging functions, by searching for the following terms:

1. Functions and classes like:
  * `Log.d`, `Log.e`, `Log.i`, `Log.v`, `Log.w` and `Log.wtf`
  * `Logger`
  * `StrictMode`

2. Keywords and system output to identify non-standard log mechanisms like :
  * logfile
  * logging
  * logs
  * `System.out.print` | `System.out.println`

#### Black-box Testing

Use the mobile app extensively so that all functionality is at least triggered once.

1. Identify the data directory of the application in order to look for log files (`/data/data/package_name`). Check if log data is generated by checking the application logs, as some mobile applications create and store their own logs in the data directory.  
2. Many application developers use still `System.out.println()` or `printStackTrace()` instead of a proper logging class. Therefore the testing approach also needs to cover all output generated by the application during starting, running and closing of it and not only the output created by the log classes. In order to verify what data is written to logfiles and printed directly by using `System.out.println()` or `printStackTrace()` the code should be checked for these functions and the tool [_LogCat_][99e277eb] can be used to check the output. Two different approaches are available to execute LogCat.
  * LogCat is already part of _Dalvik Debug Monitor Server_ (DDMS) and is built into Android Studio. If the app is in debug mode and running, the log output is shown in the Android Monitor in the LogCat tab. Patterns can be defined in LogCat to filter the log output of the app.

![Log output in Android Studio](/Document/images/Testcases/OMTG-DATAST_Android/log_output_Android_Studio.png)

  * LogCat can be executed by using adb in order to store the log output permanently.

```bash
# adb logcat > logcat.log
```

#### Remediation

Ensure logging statements are removed from the production release, as logs may be interrogated or readable by other applications. Tools like **[ProGuard][45476f61]**, which is already included in Android Studio or **[DexGuard][7bd6e70d]** can be used to strip out logging portions in the code when preparing the production release. For example, to remove logging calls within an android application, simply add the following option in the _proguard-project.txt_ configuration file of ProGuard:

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

#### References

##### Info
* [Overview of Class Log][de2ec1fd]
* [Debugging Logs with LogCat][7f106169]

##### Tools
* [LogCat][99e277eb]
* [ProGuard][45476f61]
* [DexGuard][7bd6e70d]
* [ClassyShark][c83d7c35]

##### OWASP MASVS

- V2.2: "No sensitive data is written to application logs."

##### OWASP Mobile Top 10
* M1 - Improper Platform Usage
* M2 - Insecure Data Storage

##### CWE
* CWE-117: Improper Output Neutralization for Logs
* CWE-532: Information Exposure Through Log Files
* CWE-534: Information Exposure Through Debug Log Files


### <a name="OMTG-DATAST-003"></a>OMTG-DATAST-003: Test for Sensitive Data in Cloud Storage

#### Overview

Android provides two ways for Apps to backup their data to the cloud:
* Auto Backup for Apps in Android 6.0 (available >= API level 23), which uploads the data to the users Google Drive account.
* Key/Value Backup (Backup API), which uploads the data to the Android Backup Service.

#### White-box Testing

Regardless of using either key/value or auto backup, it need to be identified:
* what files are sent to the cloud (e.g. SharedPreferences),
* if the files contain sensitive information,
* if sensitive information is protected through encryption before sending it to the cloud.

##### Auto Backup
When setting the attribute `android:allowBackup` to true in the manifest file, auto backup is enabled. If this attribute is not available auto backup is enabled by default. Therefore it need to be explicitly disabled in order to deactivate it.

```xml
<application ...
    android:allowBackup="true">
</app>
```

The attribute `android:fullBackupOnly` can also be used to activate auto backup when implementing a backup agent, but this is only  available for Android 6.0 onwards. Oder Android version will be using key/value backup instead.

```xml
android:fullBackupOnly
```

Auto backup includes almost all of the App's files and stores them in the Google Drive account of the user, limited to 25MB per App. Only the most recent backup is stored, the previous backup is deleted.

##### Key/Value Backup
To enable key/value backup the backup agent need to be defined in the manifest file. Look in `AndroidManifest.xml` for the following attribute:

```xml
android:backupAgent
```

To implement the key/value backup, either one of the following classes need to be extended:
* BackupAgent
* BackupAgentHelper


#### Black-box Testing

The APK should be decompiled in order to read the manifest file **[LINK TO GUIDE TO DECOMPILE APK]**. According to the attributes set, it can be identified if backup features are used or not. See White-box testing for details.

#### Remediation

Sensitive information should not be sent in clear text to the cloud. It should either be:

* avoided to store the information in the first place or
* encrypt the information in rest, before sending it to the cloud.

Files can also be excluded from Auto Backup, in case they should not be shared with the Google Cloud, see [including files][e894a591].

#### References

* [Backing up App Data to the Cloud][fd7bd757]
* [Key/Value Backup][1aee61a9]
* [BackupAgentHelper][48d8d464]
* [BackupAgent][03c7b547]
* [Auto Backup][bf8bd4ca]

##### OWASP MASVS

- V2.3: "No sensitive data is synced with cloud storage."

##### OWASP Mobile Top 10
* M1 - Improper Platform Usage
* M2 - Insecure Data Storage

##### CWE
- CWE-200: Information Exposure [https://cwe.mitre.org/data/definitions/200.html]


### <a name="OMTG-DATAST-004"></a>OMTG-DATAST-004: Test Whether Sensitive Data is Sent to Third Parties

#### Overview

Different 3rd party services are available that can be embedded into the App to implement different features. This features can vary from tracker services to monitor the user behaviour within the App, selling banner advertisements or to create a better user experience. Interacting with these services abstracts the complexity and neediness to implement the functionality on it’s own and to reinvent the wheel.
The downside is that a developer doesn’t know in detail what code is executed via 3rd party libraries and therefore giving up visibility. Consequently it should be ensured that not more information as needed is sent to the service and that no sensitive information is disclosed.

3rd party services are mostly implemented in two ways:
* By using a standalone library, like a Jar in an Android project that is getting included into the APK.
* By using a full SDK.

#### White-box Testing

Some 3rd party libraries can be automatically integrated into the App through a wizard within the IDE. The permissions set in the `AnroidManifest.xml`  when installing a library through an IDE wizard should be reviewed. Especially permissions to access `SMS (READ_SMS)`, contacts (`READ_CONTACTS`) or the location (`ACCESS_FINE_LOCATION`) should be challenged if they are really needed to make the library work at a bare minimum, see also **OMTG-ENV-XXX**. When talking to developers it should be shared to them that it’s actually necessary to have a look at the diff on the project source code before and after the library was installed through the IDE and what changes have been made to the code base.

The same thing applies when adding a library or SDK manually. The source code should be checked for API calls or functions provided by the 3rd party library or SDK. The applied code changes should be reviewed and it should be checked if available security best practices of the library and SDK are applied and used.

The libraries loaded into the project should be reviewed in order to identify with the developers if they are needed and also if they are out of date and contain known vulnerabilities.

#### Black-box Testing

All requests made to the external service should be analyzed if any sensitive information is embedded into them.
* Dynamic analysis can be performed by launching a Man-in-the-middle (MITM) attack using _Burp Proxy_ or OWASP ZAP, to intercept the traffic exchanged between client and server. A complete guide can be found [here][05773baa]. Once we are able to route the traffic to the interception proxy, we can try to sniff the traffic from the App. When using the App all requests that are not going directly to the server where the main function is hosted should be checked, if any sensitive information is sent to a 3rd party. This could be for example PII in a tracker or ad service.
* When decompiling the App, API calls and/or functions provided through the 3rd party library should be reviewed on a source code level to identify if they are used accordingly to best practices.

#### Remediation

All data that is sent to 3rd Party services should be anonymized, so no PII data is available. Also all other data, like IDs in an application that can be mapped to a user account or session should not be sent to a third party.  
`AndroidManifest.xml` should only contain the permissions that are absolutely needed to work properly and as intended.

#### References

* [Bulletproof Android, Godfrey Nolan][9b6055db]: Chapter 7 - Third-Party Library Integration

[9b6055db]: https://www.amazon.com/Bulletproof-Android-Practical-Building-Developers/dp/0133993329 "Book_BulletproofAndroid"
[05773baa]: https://support.portswigger.net/customer/portal/articles/1841101-configuring-an-android-device-to-work-with-burp "ConfigureAndroidBurp"

##### OWASP MASVS

- V2.4: "No sensitive data is sent to third parties."

##### OWASP Mobile Top 10
* M1 - Improper Platform Usage
* M2 - Insecure Data Storage

##### CWE
- CWE-359 "Exposure of Private Information ('Privacy Violation')": [Link to CWE issue]

### <a name="OMTG-DATAST-005"></a>OMTG-DATAST-005: Test for Sensitive Data in the Keyboard Cache

#### Overview

When keying in data into input fields, the software keyboard automatically suggests what data the user might want to key in. This feature can be very useful in messaging Apps to write text messages more efficient. For input fields that are asking for sensitive information like passwords or credit card data the keyboard cache might disclose sensitive information already when the input field is selected. This feature should therefore be disabled for input fields that are asking for sensitive information.

#### White-box Testing

In the layout definition of an activity, TextViews can be defined that have XML attributes. When the XML attribute android:inputType is set with the constant "textNoSuggestions" the keyboard cache is not shown if the input field is selected. Only the keyboard is shown and the user needs to type everything manually and nothing is suggested to him.

```xml
   <EditText
        android:id="@+id/KeyBoardCache"
        android:inputType="textNoSuggestions"/>
```


#### Black-box Testing

Start the app and click into the input fields that ask for sensitive data. If strings are suggested the keyboard cache is not disabled for this input field.

#### Remediation

All input fields that ask for sensitive information, should implement the following XML attribute to disable the keyboard suggestions:

```xml
android:inputType="textNoSuggestions"
```

#### References

- https://developer.android.com/reference/android/text/InputType.html#TYPE_TEXT_FLAG_NO_SUGGESTIONS

##### OWASP MASVS

- V2.5: "The keyboard cache is disabled on text inputs that process sensitive data."

##### OWASP Mobile Top 10
* M1 - Improper Platform Usage
* M2 - Insecure Data Storage

##### CWE
- CWE-524: Information Exposure Through Caching


### <a name="OMTG-DATAST-006"></a>OMTG-DATAST-006: Test for Sensitive Data in the Clipboard

#### Overview

(... TODO ...)


#### White-box Testing

Input fields that are asking for sensitive information need to be identified and afterwards be investigated if any countermeasures are in place to mitigate the clipboard of showing up. See the remediation section for code snippets that could be applied.

#### Black-box Testing

Start the app and click into the input fields that ask for sensitive data. When it's possible to get the menu to copy/paste data the functionality is not disabled for this input field.

#### Remediation

Many major versions of the Android operating system are still actively used and are outta there. On top of that several mobile phone manufactures are implementing their own user interface extensions and functions to their Android fork. Because of this it might be difficult to deactivate the clipboard completely on every single Android device.

A general best practice is overwriting different functions in the input field to disable the clipboard specifically for it.

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

Also `longclickable` should be deactivated for this input field.

```xml
android:longClickable="false"
```

#### References

- https://developer.android.com/guide/topics/text/copy-paste.html

##### OWASP MASVS

- V2.6: "The clipboard is deactivated on text fields that may contain sensitive data."

##### OWASP Mobile Top 10
* M1 - Improper Platform Usage
* M2 - Insecure Data Storage

##### CWE
- CWE: [Link to CWE issue]

### <a name="OMTG-DATAST-007"></a>OMTG-DATAST-007: Test If Sensitive Data Is Exposed via IPC Mechanisms

#### Overview

During development of mobile application, traditional techniques for IPC might be applied like usage of shared files or network sockets. As mobile application platforms implement their own system functionality for IPC these mechanisms should be applied as they are much more mature than traditional techniques. Using IPC mechanisms with no security in mind may cause the application to leak or expose sensitive data.

The following is a list of Android IPC Mechanisms that may expose sensitive data:
* [Binders][0c656fa2]
* [Services][d97f5ea9]
  * [Bound Services][5a7bc786]
  * [AIDL][8c349a63]
* [Intents][a28d43d1]
* [ContentProviders][6a30e426]

#### White-box Testing

The first step is to look into the `AndroidManifest.xml` in order to detect and identify IPC mechanisms exposed by the App. You will want to identify elements such as:

* `<intent-filter>`: more [here][aa2cf4d9]
* `<service>`: more [here][56866a0a]
* `<provider>`: more [here][466ff32c]
* `<receiver>`: more [here][988bd8a2]

Except for the `<intent-filter>` element, check if the the previous elements contain the following attributes:
* `android:exported`
* `android:permission`

Once you identify a list of IPC mechanisms, review the source code in order to detect if they leak any sensitive data when used. For example, _ContentProviders_ can be used to access database information, while services can be probed to see if they return data. Also BroadcastReceiver and Broadcast intents can leak sensitive information if probed or sniffed.

* Vulnerable ContentProvider

An example of vulnerable _ContentProvider_ (and SQL injection **#TODO: refere any input validation test in the project**)

* `AndroidManifest.xml`

```xml
<provider android:name=".CredentialProvider"
          android:authorities="com.owaspomtg.vulnapp.provider.CredentialProvider"
          android:exported="true">
</provider>
```
The application exposes the content provider. In the `CredentialProvider.java` file we have to inspect the `query` function to detect if any sensitive information will be leaked:

```java
public Cursor query(Uri uri, String[] projection, String selection,
			String[] selectionArgs, String sortOrder) {
		 SQLiteQueryBuilder queryBuilder = new SQLiteQueryBuilder();
		 // the TABLE_NAME to query on
		 queryBuilder.setTables(TABLE_NAME);
	      switch (uriMatcher.match(uri)) {
	      // maps all database column names
	      case CREDENTIALS:
	    	  queryBuilder.setProjectionMap(CredMap);
	         break;
	      case CREDENTIALS_ID:
	    	  queryBuilder.appendWhere( ID + "=" + uri.getLastPathSegment());
	         break;
	      default:
	         throw new IllegalArgumentException("Unknown URI " + uri);
	      }
	      if (sortOrder == null || sortOrder == ""){
	         sortOrder = USERNAME;
	      }
	     Cursor cursor = queryBuilder.query(database, projection, selection,
	    		  selectionArgs, null, null, sortOrder);
	      cursor.setNotificationUri(getContext().getContentResolver(), uri);
	      return cursor;
	}
```
* Vulnerable Broadcast
Search in the source code for strings like `sendBroadcast`, `sendOrderedBroadcast`, `sendStickyBroadcast` and verify that the application doesn't send any sensitive data.

An example of a vulnerable broadcast is the following:

```java
private void vulnerableBroadcastFunction() {
    // ...
    Intent VulnIntent = new Intent();
    VulnIntent.setAction("com.owasp.omtg.receiveInfo");
    VulnIntent.putExtra("ApplicationSession", "SESSIONID=A4EBFB8366004B3369044EE985617DF9");
    VulnIntent.putExtra("Username", "litnsarf_omtg");
    VulnIntent.putExtra("Group", "admin");
  }
  this.sendBroadcast(VulnIntent);
```

#### Black-box Testing

Similar to the White-box testing, you should decompile the application (if possible) and create a list of IPC mechanisms implemented by going through the AndroidManifest.xml. Once you have the list, prove each IPC via ADB or custom applications to see if they leak any sensitive information.

* Vulnerable ContentProvider

In the case of the previous content provider, we can probe the content provider via ADB, but we need to know the correct URI. Once the APK has been decompiled, use the commands `strings` and `grep` to identify the correct URI to use:

```bash
$ strings classes.dex | grep "content://"
com.owaspomtg.vulnapp.provider.CredentialProvider/credentials
```

Now you can probe the content provider via `adb` with the following command:

```bash
$ adb shell content query --uri content://com.owaspomtg.vulnapp.provider.CredentialProvider/credentials
Row: 0 id=1, username=admin, password=StrongPwd
Row: 1 id=2, username=test, password=test
...
```
* Vulnerable Broadcast

To sniff intents install and run the application on a device (actual device or emulated device) and use tools like [drozer][f3b542e2] or [Intent Sniffer][033fefeb] to capture intents and broadcast messages.


#### Remediation

For an _activity_, _broadcast_ and _service_ the permission of the caller can be checked either by code or in the manifest.

If not strictly required, be sure that your IPC does not have the `android:exported="true"` value in the `AndroidManifest.xml`, as otherwise this allows all other Apps on Android to communicate and invoke it.

If the _intent_ is only broadcast/received in the same application, `LocalBroadcastManager` can be used so that, by design, other apps cannot receive the broadcast message. This reduces the risk of leaking sensitive information. `LocalBroadcastManager.sendBroadcast().
BroadcastReceivers` should make use of the `android:permission` attribute, as otherwise any other application can invoke them. `Context.sendBroadcast(intent, receiverPermission);` can be used to specify permissions a receiver needs to have to read the broadcast. See also [sendBroadcast][2e0ef82d].
You can also set an explicit application package name that limits the components this Intent will resolve to. If left to the default value of null, all components in all applications will considered. If non-null, the Intent can only match the components in the given application package.

If your IPC is intended to be accessible to other applications, you can apply a security policy by using the `<permission>` element and set a proper `android:protectionLevel`. When using `android:permission` in a service declaration, other applications will need to declare a corresponding `<uses-permission>` element in their own manifest to be able to start, stop, or bind to the service.

#### References

* [Binders][0c656fa2]
* [Services][d97f5ea9]
* [Bound Services][5a7bc786]
* [AIDL][8c349a63]
* [Intents][a28d43d1]
* [ContentProviders][6a30e426]
* [Intent-filter][aa2cf4d9]
* [Service][56866a0a]
* [Provider][466ff32c]
* [Receiver][988bd8a2]
* [SendBroadcast][2e0ef82d]

##### OWASP MASVS

- V2.7: "No sensitive data is exposed via IPC mechanisms."

##### OWASP Mobile Top 10
* M1 - Improper Platform Usage
* M2 - Insecure Data Storage

##### CWE
- [CWE-634: Weaknesses that Affect System Processes](https://cwe.mitre.org/data/definitions/634.html)



### <a name="OMTG-DATAST-008"></a>OMTG-DATAST-008: Test for Sensitive Data in Screenshots and the Screen

#### Overview

Sensitive data could be exposed if a user deliberately takes a screenshot of the application (containing sensitive data), or in the case of malicious application running on the device, that is able to continuously capture the screen. For example, capturing a screenshot of a bank application running on the device may reveal information about the user account, his credit, transactions and so on.

Masking of sensitive data when presented within an activity of an App should also be enforced to prevent disclosure and mitigate for example shoulder surfing.

#### White-box Testing

To verify if the application may expose sensitive information via the user interface or screenshot, detect if the `[FLAG_SECURE][ee87d351]` options is set in the activity that needs to be protected.

You should be able to find something similar to the following line.

```Java
LayoutParams.FLAG_SECURE
```
If not, the application is probably vulnerable to screen capturing.

**(..TODO..) - Masking of sensitive data in input fields, how can it be implemented in Android**

### Black-box Testing

To analyse if the application leaks any sensitive information, run the application on a device and try to acquire a screenshot of the activity or activities you want to test.

Steps to reproduce:
* Install the application on an actual device or emulator
 * `adb shell install <apk_name>`
* Run the application
* Take a screenshot and save in the current folder
 * `adb shell screencap -p /sdcard/screencap.png && adb pull /sdcard/screencap.png`

If you can see the application screenshot, the application is vulnerable; otherwise you will obtain a file of 0 bytes.

![OMTG_DATAST_008_FLAG_SECURE](/Document/Images/Testcases/OMTG-DATAST_Android/3.png)

Text fields should mask the input if sensitive information need to be keyed in.

#### Remediation

In order to prevent user or malicious applications to capture the screen of a specific activity, add the following code in the `my_app.java` activity file that you want to protect, and then call `setContentView`:

```Java
getWindow().setFlags(WindowManager.LayoutParams.FLAG_SECURE,
                WindowManager.LayoutParams.FLAG_SECURE);

setContentView(R.layout.activity_main);
```

Note that this would automatically prevent the user from taking a manual screenshot. But even if the activity is tagged with `FLAG_SECURE`, this does not apply to any pop-up windows such as Dialogs, Toasts, etc.

#### References

- [FLAG_SECURE](ee87d351)

##### OWASP MASVS

- V2.8: "No sensitive data, such as passwords and credit card numbers, is exposed through the user interface or leaks to screenshots."

##### OWASP Mobile Top 10
* M4 - Unintended Data Leakage

##### CWE
- [CWE-200: Information Exposure](https://cwe.mitre.org/data/definitions/200.html)


### <a name="OMTG-DATAST-009"></a>OMTG-DATAST-009: Test for Sensitive Data in Backups

#### Overview

When backup options are available, it is important to consider that user data may be stored within application configuration data.  This feature could potentially leak sensitive information such as sessions, usernames, email addresses, passwords, keys and much more.
Consider to encrypt backup data and avoid to store any sensitive information that is not strictly required.

#### White-box Testing

In order to backup all your application’s data Android provides an attribute called `allowBackup`. This attribute is set within the `AndroidManifest.xml` file. If the value of this attribute is set to **true**, then the device allows user to backup the application using Android Debug Bridge (ADB) - `$ adb backup`.

> Note: If the device was encrypted, then the backup files will be encrypted as well.

Check the `AndroidManifest.xml` file for the following flag:

```xml
android:allowBackup="true"
```

If the value is set to **true**, investigate whether the App saves any kind of sensitive data, either by reading the source code, or inspecting the files in the App's data directory.

#### Black-box Testing

Attempt to make a backup using `adb` and, if successful, inspect the backup archive for sensitive data. Open a terminal and run the following command:

```bash
$ adb backup -apk -nosystem packageNameOfTheDesiredAPK
```

Approve the backup from your device by selecting the "_Back up my data_" option. After the backup process is finished, you will have a _.ab_ file in your current working directory.
Run the following command to convert the .ab file into a .tar file.

```bash
$ dd if=mybackup.ab bs=24 skip=1|openssl zlib -d > mybackup.tar
```

Alternatively, use the [Android Backup Extractor](https://sourceforge.net/projects/adbextractor/) for this task. To install, download the [binary distribution](https://sourceforge.net/projects/adbextractor/files/latest/download). For the tool to work, you also have to download the [Oracle JCE Unlimited Strength Jurisdiction Policy Files for JRE7](http://www.oracle.com/technetwork/java/javase/downloads/jce-7-download-432124.html) or [JRE8](http://www.oracle.com/technetwork/java/javase/downloads/jce8-download-2133166.html), and place them in the JRE lib/security folder. Run the following command to convert the tar file:

```bash
java -jar android-backup-extractor-20160710-bin/abe.jar unpack backup.ab
```

Extract the tar file into your current working directory to perform your analysis for sensitive data.

```bash
$ tar xvf mybackup.tar
```

#### Remediation

To prevent backing up the app's data, set the `android:allowBackup` attribute must be set to **false** in `AndroidManifest.xml`.

#### References

- Documentation for the Application tag: https://developer.android.com/guide/topics/manifest/application-element.html#allowbackup

##### OWASP MASVS

- V2.9: "No sensitive data is included in backups."

##### OWASP Mobile Top 10
* M1 - Improper Platform Usage
* M2 - Insecure Data Storage

##### CWE
* [CWE-530](https://cwe.mitre.org/data/definitions/530.html)


### <a name="OMTG-DATAST-010"></a>OMTG-DATAST-010: Test for sensitive information in screenshots when App is backgrounded

#### Overview

Manufacturers want to provide device users an aesthetically pleasing effect when an application is entered or exited, hence they introduced the concept of saving a screenshot when the application goes into the background. This feature could potentially pose a security risk for an application, as the screenshot containing sensitive information (e.g. a screenshot of an email or corporate documents) is written to local storage, where it is recovered either by a rogue application on a jailbroken device, or by someone who steals the device.

#### White-box Testing

In Android, when the App goes into background a screenshot of the current activity is taken and is used to give a pleasing effect when the App is next entered. However, this would leak sensitive information that is present within the App.

To verify if the application may expose sensitive information via task switcher, detect if the `[FLAG_SECURE][ee87d351]` options is set. You should be able to find something similar to the following line.

```Java
LayoutParams.FLAG_SECURE
```
If not, the application is probably vulnerable to screen capturing.

#### Black-box Testing

During black-box testing, open any screen within the App that contains sensitive information and click on Home button so that the App goes into background. Now press the task-switcher button, to see the snapshot. As showed below, if `SECURE_FLAG` is set (image on the left), the snapshot is entirely black, while if the `SECURE_FLAG` is not set (image on the right), information within the activity are shown:

| `SECURE_FLAG` not set  | `SECURE_FLAG` set  |
|---|---|
| ![OMTG_DATAST_010_1_FLAG_SECURE](/Document/Images/Testcases/OMTG-DATAST_Android/1.png)   |  ![OMTG_DATAST_010_2_FLAG_SECURE](/Document/Images/Testcases/OMTG-DATAST_Android/2.png) |


#### Remediation

To prevent users or malicious applications access information from backgrounded applications use the `SECURE_FLAG` as shown below:

```Java
getWindow().setFlags(WindowManager.LayoutParams.FLAG_SECURE,
                WindowManager.LayoutParams.FLAG_SECURE);

setContentView(R.layout.activity_main);
```

Moreover, the following suggestions can also be implemented to enhance your application security posture:
* Quit the app entirely when backgrounded. This will destroy any retained GUI screens.
* Nullify the data on a GUI screen before leaving the screen or logging out.

#### References

- [link to relevant how-tos, papers, etc.]


##### OWASP MASVS

- V2.10: "The app removes sensitive data from views when backgrounded."

##### OWASP Mobile Top 10
* M1 - Improper Platform Usage
* M2 - Insecure Data Storage

##### CWE
* [CWE-530](https://cwe.mitre.org/data/definitions/530.html)


### <a name="OMTG-DATAST-011"></a>OMTG-DATAST-011: Test for Sensitive Data in Memory

#### Overview

Analyzing the memory can help to identify the root cause of different problems, like for example why an application is crashing, but can also be used to identify sensitive data. This section describes how to check for sensitive data and disclosure of data in general within the process memory.

To be able to investigate the memory of an application a memory dump needs to be created first or the memory needs to be viewed with real-time updates. This is also already the problem, as the application only stores certain information in memory if certain functions are triggered within the application. Memory investigation can of course be executed randomly in every stage of the application, but it is much more beneficial to understand first what the mobile application is doing and what kind of functionalities it offers and also make a deep dive into the decompiled code before making any memory analysis.
Once sensitive functions are identified (like decryption of data) the investigation of a memory dump might be beneficial in order to identify sensitive data like a key or the decrypted information itself.

#### White-box Testing

It needs to be identified within the code when sensitive information is stored within a variable or processed and is therefore available within the memory. This information can then be used in dynamic testing when using the App.

#### Black-box Testing

To analyse the memory of an App, the app must be **debuggable**.
See the instructions in XXX (**#TODO-Link to repackage and sign**) on how to repackage and sign an Android App to enable debugging for an app, if not already done. Also adb integration need to be activated in Android Studio in “_Tools/Android/Enable ADB Integration_” in order to take a memory dump.

For rudimentary analysis Android Studio built in tools can be used. Android studio includes tools in the “_Android Monitor_” tab to investigate the memory. Select the device and app you want to analyse in the "_Android Monitor_" tab and click on "_Dump Java Heap_" and a _.hprof_ file will be created.

![Create Heap Dump](/Document/images/Testcases/OMTG-DATAST_Android/Dump_Java_Heap.png)

In the new tab that shows the _.hprof_ file, the Package Tree View should be selected. Afterwards the package name of the app can be used to navigate to the instances of classes that were saved in the memory dump.

![Create Heap Dump](/Document/images/Testcases/OMTG-DATAST_Android/Package_Tree_View.png)

For deeper analysis of the memory dump Eclipse Memory Analyser (MAT) should be used. The _.hprof_ file will be stored in the directory "captures", relative to the project path open within Android Studio.

Before the _.hprof_ file can be opened in MAT it needs to be converted. The tool _hprof-conf_ can be found in the Android SDK in the directory platform-tools.

```bash
./hprof-conv file.hprof file-converted.hprof
```

By using MAT, more functions are available like usage of the Object Query Language (OQL). OQL is an SQL-like language that can be used to make queries in the memory dump. Analysis should be done on the dominator tree as only this contains the variables/memory of static classes.

To quickly discover potential sensitive data in the _.hprof_ file, it is also useful to run the `string` command against it. When doing a memory analysis, check for sensitive information like:
* Password and/or Username
* Decrypted information
* User or session related information
* Session ID
* Interaction with OS, e.g. reading file content

#### Remediation

If sensitive information is used within the application memory it should be nulled immediately after usage to reduce the attack surface.

#### References

* [Securely stores sensitive data in RAM][6227fc2d]

Tools:
* [Android Studio’s Memory Monitor][c96db86c]
* [Eclipse’s MAT (Memory Analyzer Tool) standalone][681372d4]
* [Memory Analyzer which is part of Eclipse][6ff3fc11]
* [Fridump][ebd40e26]
* [Fridump Repo][faab1495]
* [LiME][6204d45e] (formerly DMD)

##### References

* OWASP MASVS

- V2.11: "The app does not hold sensitive data in memory longer than necessary, and memory is cleared explicitly after use."

##### OWASP Mobile Top 10
* M1 - Improper Platform Usage
* M2 - Insecure Data Storage

##### CWE
* CWE-316 - Cleartext Storage of Sensitive Information in Memory



### <a name="OMTG-DATAST-012"></a>OMTG-DATAST-012: Test if local storage is wiped upon remote locking

#### Overview


#### White-box Testing


#### Black-box Testing



#### Remediation



#### References

- [link to relevant how-tos, papers, etc.]

#### References

##### OWASP MASVS

- V2-12: "If a remote locking mechanism exists, local storage is wiped upon locking."

##### OWASP Mobile Top 10

##### CWE
- CWE: [Link to CWE issue]



### <a name="OMTG-DATAST-013"></a>OMTG-DATAST-013: Test Enforcement of Device-Access-Security Policy

#### Overview

Usage of mobile devices is omnipresent within every enterprise and is also ever-increasing through the _"Bring your own device"_ (BYOD) mentality. In order to be able as an enterprise to manage also personal mobile devices of the employees that are used in the corporate network, Mobile Device Management solutions are in place to achieve exactly this. Different enterprise solutions are out there and can enforce for example the following:

* Strong PIN or password to unlock the device
* Remote locking and wiping of a device when lost (see also OMTG-DATAST-012)
* Revoke access if employee leaves the company
* Usage of the latest Android OS version
* Disable USB file transfer
* Disable Hotspot usage

#### White-box Testing

In oder to be able to test the device access security policy, a copy of the policy that is enforced on the devices in scope need to be provided. This can be achieved either by:

* providing screenshots of the settings or
* export the configuration of the MDM.

Then, the enforced security settings need to be checked on a provisioned device that is managed by the MDM.

#### Black-box Testing

This test cannot be executed as a black-box test, as without proper knowledge of the enforced policy through the MDM no baseline is available to test against.

#### Remediation

**Are there any best practices what an MDM Should enforce for Android?**

#### References

- [link to relevant how-tos, papers, etc.]

#### References

##### OWASP MASVS

- V2-13: "The app enforces a minimum device-access-security policy, such as requiring the user to set a device passcode."

##### OWASP Mobile Top 10

##### CWE
- CWE: [Link to CWE issue]

<!-- References links
If a link is outdated, you can change it here and it will be updated everywhere -->

<!-- OMTG-DATAST-001-1 -->
[707361af]: http://developer.android.com/reference/android/security/KeyChain.html "Android KeyChain"
[19149717]: http://developer.android.com/training/articles/keystore.html "Android KeyStore System"
[0d4e8f69]: http://www.androidauthority.com/use-android-keystore-store-passwords-sensitive-information-623779/ "Use Android Keystore"
[8705d59b]: https://developer.android.com/reference/javax/crypto/Cipher.html "Cipher"
[c941abfc]: https://developer.android.com/reference/java/security/SecureRandom.html "SecureRandom"
[fcc82125]: https://developer.android.com/reference/javax/crypto/KeyGenerator.html "KeyGenerator"
[ff4a4029]: https://developer.android.com/reference/android/accounts/AccountManager.html "AccountManager"

<!-- OMTG-DATAST-001-2 -->
[tempfiles]: https://www.sqlite.org/tempfiles.html "Journal files"
[lockingv3]: https://www.sqlite.org/lockingv3.html "Lock Files"
[e65ea363]: http://developer.android.com/guide/topics/data/data-storage.html#filesInternal "UsingInternalStorage"
[5e4c3059]: https://developer.android.com/guide/topics/data/data-storage.html#filesExternal "UsingExternalStorage"
[afd8258f]: http://developer.android.com/reference/android/content/SharedPreferences.html "SharedPreferences"
[7e90d2dc]: https://www.zetetic.net/sqlcipher/sqlcipher-for-android/ "SQLCipher"
[6dea1401]: https://github.com/scottyab/secure-preferences "SecurePreferences"
[1e23894b]: https://developer.android.com/training/basics/data-storage/index.html "AndroidStorage"
[fb530e1c]: http://developer.android.com/training/articles/security-tips.html#StoringData "StoringData"
[be9ea354]: https://github.com/google/enjarify "Enjarify"
[b54750a7]: https://github.com/skylot/jadx "JADX"
[3d1bb980]: https://github.com/pxb1988/dex2jar "Dex2jar"
[a9965341]: http://developer.android.com/tools/help/lint.html "Lint"
[3b9b0b6f]: http://www.sqlite.org/cli.html "Sqlite3"

<!-- OMTG-DATAST-002 -->
[45476f61]: http://proguard.sourceforge.net/ "ProGuard"
[7bd6e70d]: https://www.guardsquare.com/dexguard "DexGuard"
[99e277eb]: http://developer.android.com/tools/help/logcat.html "LogCat"
[c83d7c35]: https://github.com/google/android-classyshark "ClassyShark"
[de2ec1fd]: http://developer.android.com/reference/android/util/Log.html "ClassLogOverview"
[7f106169]: http://developer.android.com/tools/debugging/debugging-log.html "DebuggingLogsLogCat"

<!-- OMTG-DATAST-003 -->
[e894a591]: https://developer.android.com/guide/topics/data/autobackup.html#IncludingFiles "IncludingFiles"
[fd7bd757]: https://developer.android.com/guide/topics/data/backup.html "BackingUpAppDataToCloud"
[1aee61a9]: https://developer.android.com/guide/topics/data/keyvaluebackup.html "KeyValueBackup"
[48d8d464]: https://developer.android.com/reference/android/app/backup/BackupAgentHelper.html "BackupAgentHelper"
[03c7b547]: https://developer.android.com/reference/android/app/backup/BackupAgent.html "BackupAgent"
[bf8bd4ca]: https://developer.android.com/guide/topics/data/autobackup.html "AutoBackup"

<!-- OMTG-DATAST-011 -->
[c96db86c]: http://developer.android.com/tools/debugging/debugging-memory.html#ViewHeap "MemoryMonitor"
[681372d4]: https://eclipse.org/mat/downloads.php "EclipseMATStandalone"
[6ff3fc11]: https://www.eclipse.org/downloads/ "MemoryAnalyzerWhichIsPartOfEclipse"
[ebd40e26]: http://pentestcorner.com/introduction-to-fridump "Fridump"
[faab1495]: https://github.com/Nightbringer21/fridump "FridumpRepo"
[6204d45e]: https://github.com/504ensicsLabs/LiME "LiME"
[6227fc2d]: https://www.nowsecure.com/resources/secure-mobile-development/coding-practices/securely-store-sensitive-data-in-ram/ "SecurelyStoreDataInRAM"

<!-- OMTG-DATAST-007 -->
[0c656fa2]: https://developer.android.com/reference/android/os/Binder.html "IPCBinder"
[d97f5ea9]: https://developer.android.com/guide/components/services.html "IPCServices"
[a28d43d1]: https://developer.android.com/reference/android/content/Intent.html "IPCIntent"
[6a30e426]: https://developer.android.com/reference/android/content/ContentProvider.html "IPCContentProviders"
[aa2cf4d9]: https://developer.android.com/guide/topics/manifest/intent-filter-element.html "IntentFilterElement"
[56866a0a]: https://developer.android.com/guide/topics/manifest/service-element.html "ServiceElement"
[466ff32c]: https://developer.android.com/guide/topics/manifest/provider-element.html "ProviderElement"
[988bd8a2]: https://developer.android.com/guide/topics/manifest/receiver-element.html "ReceiverElement"
[5a7bc786]: https://developer.android.com/guide/components/bound-services.html "BoundServices"
[8c349a63]: https://developer.android.com/guide/components/aidl.html "AIDL"
[2e0ef82d]: https://developer.android.com/reference/android/content/Context.html#sendBroadcast(android.content.Intent) "SendBroadcast"
[033fefeb]: https://www.nccgroup.trust/us/about-us/resources/intent-sniffer/ "IntentSniffer"
[f3b542e2]: https://labs.mwrinfosecurity.com/tools/drozer/ "Drozer"

<!-- OMTG-DATAST-008 -->
[ee87d351]: https://developer.android.com/reference/android/view/Display.html#FLAG_SECURE "FLAG_SECURE"
