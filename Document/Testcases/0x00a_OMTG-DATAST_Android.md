## <a name="OMTG-DATAST-001-1"></a>OMTG-DATAST-001-1: Test for system credentials storage features

### White-box Testing

Encryption operations should rely on solid and tested functions provided by the SDK. The following describes different “bad practices” that should be checked withi the source code:
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

### Black-box Testing

When targetting compiled Android applications, the best way to proceed is to first decompile them  in order to obtain something close to the source code (_**see Decompiling Android App Guide - #TODO-Create a general guide that can bee referenced anywhere in the OMSTF**_). With the code in your hands you should then be able to inspect and verify if system credentials storage facilities are in place.

### Remediation

If sensitive information (credentials, keys, PII, etc.) is needed locally on the device several best practices are offered by Android that should be used to store data securely instead of reinventing the wheel or leave it unencrypted on the device.

The following is a list of best practice used for secure storage of certificates and keys and sensitve data in general:
* [Android KeyStore][19149717]: The KeyStore provides a secure system level credential storage. It is important to note that the credentials are not actually stored within the KeyStore. An app can create a new private/public key pair to encrypt application secrets by using the public key and decrypt the same by using the private key. The KeyStores is a secure container that makes it difficult for an attacker to retrieve the private key and guards the encrypted data. Nevertheless an attacker can access all keys on a rooted device in the folder `/data/misc/keystore/`. The Keystore is encrypted using the user’s own lockscreen pin/password, hence, when the device screen is locked the Keystore is unavailable. More information can be found here: [how to use Android Keystore][0d4e8f69].
* [Android KeyChain][707361af]: The KeyChain class is used to store and retrieve private keys and their corresponding certificate (chain). The user will be prompted to set a lock screen PIN or password to protect the credential storage if it hasn’t been set, if something gets imported into the KeyChain the first time.
* Encryption or decryption functions that were self implemented need to be avoided. Instead use Android implementations such as [Cipher][8705d59b], [SecureRandom][c941abfc] and [KeyGenerator][fcc82125].   
* Username and password should not be stored on the device. Instead, perform initial authentication using the username and password supplied by the user, and then use a short-lived, service-specific authorization token (session token). If possible, use the [AccountManager][ff4a4029] class to invoke a cloud-based service and do not store passwords on the device.
* As a security in depth measure code obfuscation should also be applied to the App, to make reverse engineering harder for attackers.

### References
* [How to use the Android Keystore to store passwords and other sensitive information][0d4e8f69]
* [Android KeyChain][707361af]
* [Android KeyStore][19149717]

## <a name="OMTG-DATAST-001-2"></a>OMTG-DATAST-001-2: Test for Sensitive Data Disclosure in Local Storage
### Overview

[Storing data][fb530e1c] is essential for many mobile applications, for example in order to keep track of user settings or data a user might has keyed in that needs to stored locally or offline. Data can be stored persistently by a mobile application in various ways on each of the different operating systems. The following table shows those mechanisms that are available on the Android platform:

* Shared Preferences
* Internal Storage  
* External Storage  
* SQLite Databases  

The following examples shows snippets of code to demonstrate bad practices that discloses sensitive information and also shows the different mechanisms in Android to store data.

The following examples shows snippets of code to demonstrate bad practices that discloses sensitive information and also shows the different mechanisms in Android to store data.

#### Shared Preferences

[SharedPreferences][afd8258f] is a common approach to store Key/Value pairs persistently in the filesystem by using a XML structure. Within an Activity the following code might be used to store sensitive information like a username and a password:

```java
SharedPreferences sharedPref = getSharedPreferences("key", MODE_WORLD_READABLE);
SharedPreferences.Editor editor = sharedPref.edit();
editor.putString("username", "administrator");
editor.putString("password", "supersecret");
editor.commit();
```

> Please note that `MODE_WORLD_READABLE` and `MODE_WORLD_WRITEABLE` were deprecated in API 17. Although this may not affect newer devices, applications compiled with android:targetSdkVersion set prior to 17 may still be affected, if they run on OS prior to Android 4.2 (`JELLY_BEAN_MR1`).

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

#### SQLite Databases (Unencrypted)

SQLite is a SQL database that stores data to a text file. The Android SDK comes with built in classes to operate SQLite databases. The main package to manage the databases is android.database.sqlite.
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

#### SQLite Databases (Encrypted)

By using the library [SQLCipher][7e90d2dc] SQLite databases can be encrypted, by providing a password.
```java
SQLiteDatabase secureDB = SQLiteDatabase.openOrCreateDatabase(database, "password123", null);
secureDB.execSQL("CREATE TABLE IF NOT EXISTS Accounts(Username VARCHAR,Password VARCHAR);");
secureDB.execSQL("INSERT INTO Accounts VALUES('admin','AdminPassEnc');");
secureDB.close();

```
If encrypted SQLite databases are used, check if the password is hardcoded in the source, stored in shared preferences or hidden somewhere else in the code or file system.
A secure approach to retrieve the key, instead of storing it locally could be to either:

* Ask the user every time for a PIN or password to decrypt the database, once the App is opened (weak password or PIN is prone to Brute Force Attacks)
* Store the key on the server and make it accessible via a Web Service (then the App can only be used when the device is online)

#### Internal Storage

Files can be saved directly on the device's [internal storage][e65ea363]. By default, files saved to the internal storage are private to your application and other applications cannot access them (nor can the user). When the user uninstalls your application, these files are removed.
Within an Activity the following code might be used to store sensitive information in the variable string persistently to the internal storage:

```java
FileOutputStream fos = null;
try {
   fos = openFileOutput(FILENAME, Context.MODE_PRIVATE);
   fos.write(string.getBytes());
   fos.close();
} catch (FileNotFoundException e) {
   e.printStackTrace();
} catch (IOException e) {
   e.printStackTrace();
}
```

The file mode need to be checked, to make sure that only the app itself has access to the file by using `MODE_PRIVATE`. Other modes like `MODE_WORLD_READABLE` (deprecated) and  `MODE_WORLD_WRITEABLE` (deprecated) are more lax and can pose a security risk.

It should also be checked what files are read within the App by searching for the usage of class `FileInputStream`. Part of the internal storage mechanisms is also the cache storage. To cache data temporarily, functions like `getCacheDir()` can be used.

#### External Storage

Every Android-compatible device supports a shared "[external storage][5e4c3059]" that you can use to save files. This can be a removable storage media (such as an SD card) or an internal (non-removable) storage.
Files saved to the external storage are world-readable and can be modified by the user when they enable USB mass storage to transfer files on a computer.
Within an Activity the following code might be used to store sensitive information in the variable string persistently to the external storage:

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

### White-box Testing

As already pointed out, there are several ways to store information within Android. Several checks should therefore be applied to the source code of an Android App, once decompiled.
* Check `AndroidManifest.xml` for permissions to read and write to external storage, like `uses-permission android:name="android.permission.WRITE_EXTERNAL_STORAGE"`
* Check the source code for functions and API calls that are used for storing data:
  * Import the decompiled Java Files in an IDE of your choice (IntelliJ or Eclipse) or use grep on the command line to search for
    * file permissions like:
      * `MODE_WORLD_READABLE` or `MODE_WORLD_WRITABLE`. IPC files should not be created with permissions of `MODE_WORLD_READABLE` or `MODE_WORLD_WRITABLE` unless it is required as any app would be able to read or write the file even though it may be stored in the app’s private data directory.
    * Classes and functions like:
      * Shared Preferences (Storage of key-value pairs)
      * `FileOutPutStream` (Using Internal or External Storage)
      * `getExternal*` functions (Using External Storage)
      * `getWritableDatabase` function (return a SQLiteDatabase for writing)
      * `getReadableDatabase` function (return a SQLiteDatabase for reading)
      * `getCacheDir` and `getExternalCacheDirs` function (Using cached files)

### Black-box Testing

Install and use the App as it is intended. Afterwards check the following items:

* Check the files that are shipped with the mobile application once installed in /data/data/<AppName>/files in order to identify development, backup or simply old files that shouldn’t be in a production release.
* Check if .db files are available, which are SQLite databases and if they contain sensitive information (usernames, passwords, keys etc.). SQlite databases can be accessed on the command line with sqlite3.
* Check Shared Preferences that are stored as XML files in the shared_prefs directory of the App for sensitive information.
* Check the file system permissions of the files in /data/data/<app name>. The permission should only allow rwx to the user and his group that was created for the app (e.g. u0_a82) but not to others. Others should have no permissions to files, but may have the executable flag to directories.


### Remediation

Usage of `MODE_WORLD_WRITEABLE` or `MODE_WORLD_READABLE` should generally be avoided for files. If data needs to be shared with other applications, a content provider should be considered. A content provider offers read and write permissions to other apps and can make dynamic permission grants on a case-by-case basis.

The usage of Shared Preferences or other mechanisms that are not able to protect data should be avoided to store sensitive information. SharedPreferences are insecure and not encrypted by default.

Do not use the external storage for sensitive data. By default, files saved to the internal storage are private to your application and other applications cannot access them (nor can the user). When the user uninstalls your application, these files are removed.

To provide additional protection for sensitive data, you might choose to encrypt local files using a key that is not directly accessible to the application. For example, a key can be placed in a [KeyStore][19149717] and protected with a user password that is not stored on the device. While this does not protect data from a root compromise that can monitor the user inputting the password, it can provide protection for a lost device without file system encryption.

[“Secure-preferences][6dea1401]” can be used to encrypt the values stored within [Shared Preferences][afd8258f].


### References

#### Info

* [Internal Storage][e65ea363]
* [External Storage][5e4c3059]
* [Storing Data][fb530e1c]
* [Shared Preferences][afd8258f]
* [SQLCipher][7e90d2dc]
* [SecurePreferences][6dea1401]
* [Android Keystore][19149717]
* [Android Storage Documentation][1e23894b]

#### Tools
* [Enjarify][be9ea354]
* [JADX][b54750a7]
* [Dex2jar][3d1bb980]
* [Lint][a9965341]
* [SQLite3][3b9b0b6f]

## <a name="OMTG-DATAST-002"></a>OMTG-DATAST-002: Testing for Sensitive Data Disclosure in Log Files

### White-box Testing

Check the source code for usage of Logging functions, by searching for the following terms:

1. Function names like:
  * `Log.d`, `Log.e`, `Log.i`, `Log.v`, `Log.w` and so on
  * `Logger`
  * `StrictMode`

2. Keywords and system output to identify non-standard log mechanisms like :
  * Logfile
  * logging
  * `System.out.print` | `System.out.println`

### Black-box Testing

Use the mobile app extensively so that all functionality is at least triggered once.

1. Identify the data directory of the application in order to look for log files (`/data/data/package_name`). Check if log data is generated by checking the application logs, as some mobile applications create and store their own logs in the data directory.  
2. Many application developers use still `System.out.println()` or `printStackTrace()` instead of a proper logging class. Therefore the testing approach also needs to cover all output generated by the application during starting, running and closing of it and not only the output created by the log classes. In order to verify what data is written to `logfiles` and printed directly by using `System.out.println()` or `printStackTrace()` the code should be checked for these functions and the tool [_LogCat_][99e277eb] can be used to check the output. Two different approaches are available to execute LogCat.
  * LogCat is already part of _Dalvik Debug Monitor Server_ (DDMS) and is therefore built into Android Studio. Once the app is running and in debug mode, patterns can be defined in LogCat to reduce the log output of the app.

![Log output in Android Studio](http://bb-conservation.de/sven/adb.png)

  * LogCat can be executed by using adb in order to store the log output permanently.

```bash
# adb logcat > logcat.log
```

### Remediation

Ensure logging statements are removed from the production release, as logs may be interrogated or readable by other applications. Tools like **[ProGuard][45476f61]**, which is already included in Android Studio or **[DexGuard][7bd6e70d]** can be used to strip out logging portions in the code when preparing the production release. For example, to remove logging calls within an android application, simply add the following option in the _proguard-project.txt_ configuration file of Proguard:

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

Although the `android:debuggable=""` flag can be bypassed by repacking the application, before shipping it, it is important to set the option `android:debuggable="false"` in the _AndroidManifest.xml_.

### References

#### Info
* [Overview of Class Log][de2ec1fd]
* [Debugging Logs with LogCat][7f106169]

#### Tools
* [LogCat][99e277eb]
* [ProGuard][45476f61]
* [DexGuard][7bd6e70d]
* [ClassyShark][c83d7c35]

## <a name="OMTG-DATAST-003"></a>OMTG-DATAST-003: Test that no sensitive data leaks to cloud storage

### White-box Testing

To enable key/value backup the backup agent need to be defined in the manifest file. Look in AndroidManifest.xml for the following attribute:

```xml
android:backupAgent
```

To implement the key/value backup, either one of the following classes need to be extended:

* BackupAgent
* BackupAgentHelper

When using the following attribute in the manifest file, auto backup is used instead of key/value backup:

```xml
android:fullBackupOnly 
```
If one of these mechanisms is used in the code it need to be identified
* what files are sent to the cloud (e.g. SharedPreferences),
* if the files contain sensitive information,
* if sensitive information is protected through encryption before sending it to the cloud.


### Black-box Testing

The APK should be decompiled in order to read the manifest file. According to the attributes set, it can be identified if backup features are used or not. See White-box testing for details. 

### Remediation

Sensitive information should not be sent in clear text to the cloud. It should either be:

* avoided to store the information in the first place or
* encrypt the information in rest, before sending it to the cloud.


### References

* Backing up App Data to the Cloud - https://developer.android.com/guide/topics/data/backup.html
* Key/Value Backup - https://developer.android.com/guide/topics/data/keyvaluebackup.html
* BackupAgentHelper https://developer.android.com/reference/android/app/backup/BackupAgentHelper.html


## <a name="OMTG-DATAST-004"></a>OMTG-DATAST-004: Test for sending sensitvie data to 3rd Parties

### White-box Testing

Some 3rd party libraries can be automatically integrated into the App through a wizard within the IDE. The permissions set in the `AnroidManifest.xml`  when installing a library through an IDE wizard should be reviewed. Especially permissions to access `SMS (READ_SMS)`, contacts (`READ_CONTACTS`) or the location (`ACCESS_FINE_LOCATION`) should be challenged if they are really needed to make the library work at a bare minimum, see also OMTG-ENV-XXX. When talking to developers it should be shared to them that it’s actually necessary to have a look at the diff on the project source code before and after the library was installed through the IDE and what changes have been made to the code base.

The same thing applies when adding a library manually. The source code should be checked for API calls or functions provided by the 3rd party library. The applied code changes should be reviewed and it should be checked if available security best practices of the library are applied and used.


### Black-box Testing

All requests made to the external service should be analyzed if any sensitive information is embedded into them.
* Dynamic analysis can be performed launching a MITM attack using _Burp Proxy_, to intercept the traffic exchanged between client and server. Using the certificate provided by Portswigger, Burp can intercept and decrypt the traffic on the fly and manipulate it as you prefer. First of all we need to setup Burp, on our laptop, to listen on a specific port from all the interfaces. After that we can setup the Android device to redirect all the traffic to our laptop, i.e. setting our laptop IP address like proxy.
A complete guide can be found [here][05773baa]. Once we are able to route the traffic to burp, we can try to sniff the traffic from the application. When using the App all requests that are not going directly to the server where the main function is hosted should be checked, if any sensitive information is sent to a 3rd party. This could be for example PII in a tracker or ad service.
* When decompiling the App, API calls and/or functions provided through the 3rd party library should be reviewed on a source code level to identify if they are used accordingly to best practices.
The Jar files loaded into the project should be reviewed in order to identify with the developers if they are needed and also if they are out of date and contain known vulnerabilities.


### Remediation

All data that is sent to 3rd Party services should be anonymized, so no PII data is available. Also all other data, like IDs in an application that can be mapped to a user account or session should not be sent to a third party.  
`AndroidManifest.xml` should only contain the permissions that are absolutely needed to work properly and as intended.

### References

* [Bulletproof Android, Godfrey Nolan][9b6055db]: Chapter 7 - Third-Party Library Integration

[9b6055db]: https://www.amazon.com/Bulletproof-Android-Practical-Building-Developers/dp/0133993329 "Book_BulletproofAndroid"
[05773baa]: https://support.portswigger.net/customer/portal/articles/1841101-configuring-an-android-device-to-work-with-burp "ConfigureAndroidBurp"

## <a name="OMTG-DATAST-005"></a>OMTG-DATAST-005: Test that keyboard cache is disabled for sensitive data

### White-box Testing

In the layout definition of an activity TextViews can be defined that have XML attributes. When the XML attribute android:inputType is set with the constant "textNoSuggestions" the keyboard cache is not shown if the input field is selected. Only the keyboard is shown and the user needs to type everytyhing manually and nothing is suggested to him.

```xml
   <EditText
        android:id="@+id/KeyBoardCache"
        android:inputType="textNoSuggestions"/>
````


### Black-box Testing

Start the app and click into the input fields that ask for sensitive data. If strings are suggested the keyboard cache is not disabled for this input field.

### Remediation

All input fields that ask for sensitive information, should implement the following XML attribute to disable the keyboard suggestions:

android:inputType="textNoSuggestions"


### References

- https://developer.android.com/reference/android/text/InputType.html#TYPE_TEXT_FLAG_NO_SUGGESTIONS



## <a name="OMTG-DATAST-006"></a>OMTG-DATAST-006: Test that clipboard is deactivated for sensitive input fields

### White-box Testing

(Describe how to assess this with access to the source code and build configuration)

### Black-box Testing

[Describe how to test for this issue using static and dynamic analysis techniques. This can include everything from simply monitoring aspects of the app’s behavior to code injection, debugging, instrumentation, etc. ]

### Remediation

[Describe the best practices that developers should follow to prevent this issue]

### References

- [link to relevant how-tos, papers, etc.]



## <a name="OMTG-DATAST-007"></a>OMTG-DATAST-007: Test that no sensitive data is exposed via IPC mechanisms


### White-box Testing

(Describe how to assess this with access to the source code and build configuration)

### Black-box Testing

[Describe how to test for this issue using static and dynamic analysis techniques. This can include everything from simply monitoring aspects of the app’s behavior to code injection, debugging, instrumentation, etc. ]

### Remediation

[Describe the best practices that developers should follow to prevent this issue]

### References

- [link to relevant how-tos, papers, etc.]


## <a name="OMTG-DATAST-008"></a>OMTG-DATAST-008: Test that no sensitive data is exposed via the user interface or screenshots


### White-box Testing

(Describe how to assess this with access to the source code and build configuration)

### Black-box Testing

[Describe how to test for this issue using static and dynamic analysis techniques. This can include everything from simply monitoring aspects of the app’s behavior to code injection, debugging, instrumentation, etc. ]

### Remediation

[Describe the best practices that developers should follow to prevent this issue]

### References

- [link to relevant how-tos, papers, etc.]




## <a name="OMTG-DATAST-009"></a>OMTG-DATAST-009: Test for Sensitive Data in Backups

### White-box Testing

In order to backup all your application’s data Android provides an attribute called allowBackup. This attribute is set within the AndroidManifest.xml file. If the value of this attribute is set to true then the device allows user to backup the application using Android Debug Bridge (ADB) - $adb backup. Note: If the device was encrypted then the backup files will be encrypted as well.

Check the AndroidManifest.xml file for the following flag:

```
android:allowBackup="true"
```

If the value is set to true, investigate whether the app saves any kind of sensitive data, either by reading the source code, or inspeciting the files in the app's data directory.

### Black-box Testing

Attempt to make a backup using adb and, if successful, inspect the backup archive for sensitive data. Open a terminal and run the following command:

```
$ adb backup -apk -nosystem packageNameOfTheDesiredAPK
```

Approve the backup from your device by selecting the "Back up my data" option. After the backup process is finished, you will have a .ab file in your current working directory.
Run the following command to convert the .ab file into a .tar file.

```
$ dd if=mybackup.ab bs=24 skip=1|openssl zlib -d > mybackup.tar
```

Alternatively, use the [Android Backup Extractor](https://sourceforge.net/projects/adbextractor/) for this task. To install, download the [binary distribution](https://sourceforge.net/projects/adbextractor/files/latest/download). For the tool to work, you also have to download the [Oracle JCE Unlimited Strength Jurisdiction Policy Files for JRE7](http://www.oracle.com/technetwork/java/javase/downloads/jce-7-download-432124.html) or [JRE8](http://www.oracle.com/technetwork/java/javase/downloads/jce8-download-2133166.html), and place them in the JRE lib/security folder. Run the following command to convert the tar file:

```
java -jar android-backup-extractor-20160710-bin/abe.jar unpack backup.ab
```

Extract the tar file into your current working directory to perform your analysis for sensitive data.

```
$ tar xvf mybackup.tar
```

### Remediation

To prevent backing up the app's data, set the android:allowBackup attribute must be set to false in AndroidManifest.xml.

### References

- Documentation for the Application tag: https://developer.android.com/guide/topics/manifest/application-element.html#allowbackup



## <a name="OMTG-DATAST-010"></a>OMTG-DATAST-010: Test that no sensitive data leaks when backgrounded


### White-box Testing

(Describe how to assess this with access to the source code and build configuration)

### Black-box Testing

[Describe how to test for this issue using static and dynamic analysis techniques. This can include everything from simply monitoring aspects of the app’s behavior to code injection, debugging, instrumentation, etc. ]

### Remediation

[Describe the best practices that developers should follow to prevent this issue]

### References

- [link to relevant how-tos, papers, etc.]


## <a name="OMTG-DATAST-011"></a>OMTG-DATAST-011: Test for Sensitive Data Disclosure in Process Memory


### White-box Testing

It needs to be identified within the code when sensitive information is stored within a variable and is therefore available within the memory. This information can then be used in dynamic testing when using the App.

### Black-box Testing

To analyse the memory of an app, the app must be debuggable. See the instructions in XXX on how to repackage and sign an Android App to enable debugging for an app, if not already done. Also ADB integration need to be activated in Android Studio in “Tools/Android/Enable ADB Integration” in order to take a memory dump.
For rudimentary analysis Android Studio built in tools can be used. Android studio includes tools in the “Android Monitor” tab to investigate the memory. Select the device and app you want to analyse in the "Android Monitor" tab and click on "Dump Java Heap" and a .hprof file will be created.

![Create Heap Dump](http://bb-conservation.de/sven/mem0.png)

In the new tab that shows the .hprof file, the Package Tree View should be selected. Afterwards the package name of the app can be used to navigate to the instances of classes that were saved in the memory dump.

![Create Heap Dump](http://bb-conservation.de/sven/mem1.png)

For more deeper analysis of the memory dump Eclipse Memory Analyser (MAT) should be used. The .hprof file will be stored in the directory "captures", relative to the project path open within Android Studio.

Before the hprof file can be opened in MAT the hprof file needs to be converted. The tool hprof-conf can be found in the Android SDK in the directory platform-tools.

```
./hprof-conv file.hprof file-converted.hprof
```

By using MAT, more functions are available like usage of the Object Query Language (OQL). OQL is an SQL-like language that can be used to make queries in the memory dump. Analysis should be done on the dominator tree as only this contains the variables/memory of static classes.

When doing a memory analysis check for sensitive information like:
* Password and/or Username
* Decrypted information
* User or session related information
* Session ID
* Interaction with OS, e.g. reading file content


### Remediation

If sensitive information is used within the application memory it should be nulled immediately after usage to reduce the attack surface. Information should not be stored in clear text in memory (does this make sense?).


### References

* Securely stores sensitive data in RAM - https://www.nowsecure.com/resources/secure-mobile-development/coding-practices/securely-store-sensitive-data-in-ram/

Tools:
* Android Studio’s Memory Monitor - http://developer.android.com/tools/debugging/debugging-memory.html#ViewHeap
* Eclipse’s MAT (Memory Analyzer Tool) standalone - https://eclipse.org/mat/downloads.php
* Memory Analyzer which is part of Eclipse - https://www.eclipse.org/downloads/
* Fridump - http://pentestcorner.com/introduction-to-fridump
* Fridump Repo - https://github.com/Nightbringer21/fridump
* LiME (formerly DMD) - https://github.com/504ensicsLabs/LiME





## <a name="OMTG-DATAST-012"></a>OMTG-DATAST-012: Test support of Hardware-Backed Keystore

### White-box Testing

(Describe how to assess this with access to the source code and build configuration)

### Black-box Testing

[Describe how to test for this issue using static and dynamic analysis techniques. This can include everything from simply monitoring aspects of the app’s behavior to code injection, debugging, instrumentation, etc. ]

### Remediation

[Describe the best practices that developers should follow to prevent this issue]

### References

- [link to relevant how-tos, papers, etc.]



## <a name="OMTG-DATAST-013"></a>OMTG-DATAST-013: Test remote locking and wiping

### White-box Testing

(Describe how to assess this with access to the source code and build configuration)

### Black-box Testing

[Describe how to test for this issue using static and dynamic analysis techniques. This can include everything from simply monitoring aspects of the app’s behavior to code injection, debugging, instrumentation, etc. ]

### Remediation

[Describe the best practices that developers should follow to prevent this issue]

### References

- [link to relevant how-tos, papers, etc.]



## <a name="OMTG-DATAST-014"></a>OMTG-DATAST-014: Test for device access security policy

### White-box Testing

(Describe how to assess this with access to the source code and build configuration)

### Black-box Testing

[Describe how to test for this issue using static and dynamic analysis techniques. This can include everything from simply monitoring aspects of the app’s behavior to code injection, debugging, instrumentation, etc. ]

### Remediation

[Describe the best practices that developers should follow to prevent this issue]

### References

- [link to relevant how-tos, papers, etc.]



## <a name="OMTG-DATAST-015"></a>OMTG-DATAST-015: Test for usage of hardware-based SE or TEE

### White-box Testing

(Describe how to assess this with access to the source code and build configuration)

### Black-box Testing

[Describe how to test for this issue using static and dynamic analysis techniques. This can include everything from simply monitoring aspects of the app’s behavior to code injection, debugging, instrumentation, etc. ]

### Remediation

[Describe the best practices that developers should follow to prevent this issue]

### References

- [link to relevant how-tos, papers, etc.]


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
