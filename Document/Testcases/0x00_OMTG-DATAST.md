# Testing Data Storage

## Overview

[Describe what this chapter is about.]

## Test Cases

### OMTG-DATAST-001: Test Sensitive Data Storage
Mobile operating systems offer different native functions to store sensitive information like credentials and keys encrypted within the device. In case credentials or keys needs to be stored, several best practices available on the OS level should be applied to make it harder for attackers to retrieve these information.

The following tasks should be done when analysing an App:
* Identify keys and passwords in the App, e.g. entered by the users, sent back by the endpoint, shipped within the App and how this sensitive data is processed locally.
* Decide with the developers if this sensitive stored information locally is needed and if not, how it can be removed or moved to the server (endpoint).

#### Detailed Guides

- [OMTG-DATAST-001 Android](0x00a_OMTG-DATAST_Android.md#OMTG-DATAST-001)
- [OMTG-DATAST-001 iOS](0x00b_OMTG-DATAST_iOS.md#OMTG-DATAST-001)

#### References

##### OWASP MASVS: V2.1: Data Storage and Privacy requirements:
* Verify that system credential storage facilities are used appropriately to store sensitive data, such as user credentials or cryptographic keys.

##### OWASP Mobile Top 10
* M1 - Improper Platform Usage
* M2 - Insecure Data Storage

##### CWE
* CWE-312 - Cleartext Storage of Sensitive Information
* CWE-522 - Insufficiently Protected Credentials



### <a name="OMTG-DATAST-004"></a>OMTG-DATAST-001: Test for Sensitive Data Disclosure in Local Storage

Storing data is essential for many mobile applications, for example in order to keep track of user settings or data a user might has keyed in that needs to stored locally or offline. Data can be stored persistently by a mobile application in various ways on each of the different operating systems. The following table shows those mechanisms that are available on the Android platform:

* Shared Preferences
* Internal Storage  
* External Storage  
* SQLite Databases  

The credo for saving data can be summarized quite easy: Public data should be available for everybody, but sensitive and private data needs to be protected or not stored in the first place on the device itself.  
This vulnerability can have many consequences, like disclosure of encryption keys that can be used by an attacker to decrypt information. More generally speaking an attacker might be able to identify these information to use it as a basis for other attacks like social engineering (when PII is disclosed), session hijacking (if session information or a token is disclosed) or gather information from apps that have a payment option in order to attack it.

This vulnerability occurs when sensitive data is not properly protected by an app when persistently storing it. The app might be able to store it in different places, for example locally on the device or on an external SD card.
When trying to exploit this kind of issues, consider that there might be a lot of information processed and stored in different locations. It is important to identify at the beginning what kind of information is processed by the mobile application and keyed in by the user and what might be interesting and valuable for an attacker (e.g. passwords, credit card information).

The following examples shows snippets of code to demonstrate bad practices that discloses sensitive information and also shows the different mechanisms in Android to store data.

The following examples shows snippets of code to demonstrate bad practices that discloses sensitive information and also shows the different mechanisms in Android to store data.

#### Shared Preferences

SharedPreferences is a common approach to store Key/Value pairs persistently in the filesystem by using a XML structure. Within an Activity the following code might be used to store sensitive information like a username and a password:

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

By using the library SQLCipher SQLite databases can be encrypted, by providing a password.
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

Files can be saved directly on the device's internal storage. By default, files saved to the internal storage are private to your application and other applications cannot access them (nor can the user). When the user uninstalls your application, these files are removed [1].
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

Every Android-compatible device supports a shared "external storage" that you can use to save files. This can be a removable storage media (such as an SD card) or an internal (non-removable) storage.
Files saved to the external storage are world-readable and can be modified by the user when they enable USB mass storage to transfer files on a computer [2].
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

#### Detailed Guides

- [OMTG-DATAST-001 Android](0x00a_OMTG-DATAST_Android.md#OMTG-DATAST-001.1)
- [OMTG-DATAST-001 iOS](0x00b_OMTG-DATAST_iOS.md#OMTG-DATAST-001)

#### References

* to add

### OMTG-DATAST-009: Test for Sensitive Data in Backups
[General description]

#### Detailed Guides

- [OMTG-DATAST-009 Android](0x00a_OMTG-DATAST_Android.md#OMTG-DATAST-009)
- [OMTG-DATAST-009 iOS](0x00b_OMTG-DATAST_iOS.md#OMTG-DATAST-009)

#### References

- OWASP MASVS: V2-1: "Verify that system credential storage facilities are used appropriately to store sensitive data, such as user credentials or cryptographic keys."
- CWE: [Link to CWE issue]
