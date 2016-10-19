## <a name="OMTG-DATAST-001"></a>OMTG-DATAST-001: Test for Insecure Storage of Credentials and Keys

Mobile operating systems offer different native functions to store sensitive information like credentials and keys encrypted within the device. In case credentials or keys needs to be stored, several best practices available on the OS level should be applied to make it harder for attackers to retrieve these information. 

The following tasks should be done when analysing an App:
* Identify keys and passwords in the App, e.g. entered by the users, sent back by the endpoint, shipped within the App and how this sensitive data is processed locally. 
* Decide with the developers if this sensitive stored information locally is needed and if not, how it can be removed or moved to the server (endpoint). 

### OWASP Mobile Top 10
M1 - Improper Platform Usage
M2 - Insecure Data Storage

### CWE
CWE-312 - Cleartext Storage of Sensitive Information
CWE-522 - Insufficiently Protected Credentials

### White-box Testing

Encryption operations should rely on solid and tested functions provided by the SDK. The following describes different “bad practices” that should be checked withi the source code:
* Check if simple bit operations are used, like XOR or Bit flipping to “encrypt” sensitive information like credentials or private keys that are stored locally. This should be avoided as the data can easily be recovered. 
* Check if keys are created or used without taking advantage of the Android onboard features like the KeyStore. 
* Identify what kind of information is stored persistently and if credentials or keys are disclosed.

The code should be analysed if sensitive data is used properly and securely:
* Sensitive information should not be stored for too long in the RAM (see also “Testing for Sensitive Data Disclosure in Process Memory (OMTG-DATAST-XXX)”).
* Set variables that use sensitive information to null once finished. 
* Use immutable objects for sensitive data so it cannot be changed.

If sensitive information needs to be stored on the device itself, several functions/API calls are available to protect the data on the Android device by using the KeyChain and Keystore. The following best practices should therefore be used:
* Check if a key pair is created within the App by looking for the class KeyPairGenerator.
* Check that the application is using the KeyStore and Cipher mechanisms to securely store encrypted information on the device. Look for the pattern “import java.security.KeyStore" and “import javax.crypto.Cipher” and it’s usage. Encryption or decryption functions that were self implemented need to be avoided.   
* The store(OutputStream stream, char[] password) function can be used to store the KeyStore to disk with a specified password. Check that the password provided is not hardcoded and is defined by user input as this should only be known to the user. Look for the pattern “.store(“.



### Black-box Testing

For black box testing, the memory should be analysed in order to be able to retrieve sensitive information, like private keys related to the encryption process. See also OMTG-DATAST-XXX.
Check if keys or credentials are logged in log files (OMTG-DATAST-XXX) or stored permanently unencrypted in the file system (OMTG-DATAST-XXX). 


### Remediation

If sensitive information is needed locally on the device several best practices are offered by Android and iOS that should be used to store data securely instead of reinventing the wheel or leave it unencrypted on the device. 
Username and password should not be stored on the device. Instead, perform initial authentication using the username and password supplied by the user, and then use a short-lived, service-specific authorization token (session token).
If credentials, keys or other sensitive information need to be stored locally and are only used by one application on the device use the KeyStore to create a keypair and use it for encrypting the information. 

The following is a list of best practice functions used for secure storage of certificates and keys:
 
* KeyStore [3]: The KeyStore provides a secure system level credential storage. It is important to note that the credentials are not actually stored within the KeyStore. An app can create a new private/public key pair to encrypt application secrets by using the public key and decrypt the same by using the private key. The KeyStores is a secure container that makes it difficult for an attacker to retrieve the private key and guards the encrypted data. Nevertheless an attacker can access all keys on a rooted device in the folder /data/misc/keystore/. 	Although the Android Keystore provider was introduced in API level 18 (Android 4.3), the Keystore itself has been available since API 1, restricted to use by VPN and WiFi systems. The Keystore is encrypted using the user’s own lockscreen pin/password, hence, when the device screen is locked the Keystore is unavailable [1].	
* KeyChain [2]: The KeyChain class is used to store and retrieve private keys and their corresponding certificate (chain). The user will be prompted to set a lock screen PIN or password to protect the credential storage if it hasn’t been set, if something gets imported into the KeyChain the first time.


### References

[1] How to use the Android Keystore to store passwords and other sensitive information  - http://www.androidauthority.com/use-android-keystore-store-passwords-sensitive-information-623779/

[2] Android KeyChain - http://developer.android.com/reference/android/security/KeyChain.html 

[3] Android KeyStore System - http://developer.android.com/training/articles/keystore.html




## <a name="OMTG-DATAST-004"></a>OMTG-DATAST-001: Test for Sensitive Data Disclosure in Local Storage

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

#### Shared Preferences

SharedPreferences is a common approach to store Key/Value pairs persistently in the filesystem by using a XML structure. Within an Activity the following code might be used to store sensitive information like a username and a password:

```
SharedPreferences sharedPref = getSharedPreferences("key", MODE_WORLD_READABLE);
SharedPreferences.Editor editor = sharedPref.edit();
editor.putString("username", "administrator");
editor.putString("password", "supersecret");
editor.commit();
```

Once the activity is called, the file key.xml is created with the provided data. This code is violating several best practices. 

  * The username and password is stored in clear text in /data/data/<PackageName>/shared_prefs/key.xml

![Shared Preferences](http://bb-conservation.de/sven/shared_prefs.png)

  * MODE_WORLD_READABLE allows all applications to access and read the content of key.xml

![MODE_WORLD_READABLE](http://bb-conservation.de/sven/mode_world_readable.png)

The usage of Shared Preferences or other mechanisms that are not able to protect data should be avoided to store sensitive information. SharedPreferences are insecure and not encrypted by default. 

#### SQLite Databases (Unencrypted)

SQLite is a SQL database that stores data to a text file. The Android SDK comes with built in classes to operate SQLite databases. The main package to manage the databases is android.database.sqlite.
Within an Activity the following code might be used to store sensitive information like a username and a password:
SQLiteDatabase notSoSecure = openOrCreateDatabase("privateNotSoSecure",MODE_PRIVATE,null);

```
notSoSecure.execSQL("CREATE TABLE IF NOT EXISTS Accounts(Username VARCHAR,Password VARCHAR);");
notSoSecure.execSQL("INSERT INTO Accounts VALUES('admin','AdminPass');");
notSoSecure.close();
```

Once the activity is called, the database file privateNotSoSecure is created with the provided data and the data is stored in clear text in /data/data/<PackageName>/databases/privateNotSoSecure.
There might be several files available in the databases directory, besides the SQLite database.
  * Journal files: These are temporary files used to implement atomic commit and rollback capabilities in SQLite (see also https://www.sqlite.org/tempfiles.html). 
  * Lock files: The lock files are part of the locking and journaling mechanism designed to improve concurrency in SQLite and to reduce the writer starvation problem. (https://www.sqlite.org/lockingv3.html) 
  
Unencrypted SQLite databases should not be used to store sensitive information. 

#### SQLite Databases (Encrypted)
By using the library SQLCipher SQLite databases can be encrypted, by providing a password. 

SQLiteDatabase secureDB = SQLiteDatabase.openOrCreateDatabase(database, "password123", null);

```
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

```
FileOutputStream fos = null;
fos = openFileOutput(FILENAME, Context.MODE_PRIVATE);
fos.write(string.getBytes());
fos.close();
```

Once the activity is called, the file is created with the provided data and the data is stored in clear text in /data/data/[PackageName]/files/$FILENAME.
The file mode need to be checked, to make sure that only the app itself has access to the file by using MODE_PRIVATE. Other modes like MODE_WORLD_READABLE and  MODE_WORLD_WRITEABLE are more lax and can pose a security risk. 

It should also be checked what files are read within the App by searching for the usage of class FileInputStream. Part of the internal storage mechanisms is also the cache storage. To cache data temporarily, functions like getCacheDir() can be used. 

#### External Storage
Every Android-compatible device supports a shared "external storage" that you can use to save files. This can be a removable storage media (such as an SD card) or an internal (non-removable) storage. Files saved to the external storage are world-readable and can be modified by the user when they enable USB mass storage to transfer files on a computer [2].
Within an Activity the following code might be used to store sensitive information in the variable string persistently to the external storage:

```
File file = new File (Environment.getExternalStorageDirectory(), "password.txt");
String password = "SecretPassword";
FileOutputStream fos;
fos = new FileOutputStream(file);
fos.write(password.getBytes());
fos.close();
```

Once the activity is called, the file is created with the provided data and the data is stored in clear text in the external storage. 


### OWASP Mobile Top 10
M2 - Insecure Data Storage

### CWE 
CWE-200 - Information Exposure

### White-box Testing

As already pointed out, there are several ways to store information within Android. Several checks should therefore be applied to the source code of an Android App. 

* Check AndroidManifest.xml for permissions to read and write to external storage, like uses-permission android:name="android.permission.WRITE_EXTERNAL_STORAGE".
* Check the source code for functions and API calls that are used for storing data and search for:
  * file permissions like MODE_WORLD_READABLE or MODE_WORLD_WRITABLE. IPC files should not be created with permissions of MODE_WORLD_READABLE or MODE_WORLD_WRITABLE unless it is required as any app would be able to read or write the file even though it may be stored in the app’s private data directory.
* Check the source code for functions and API calls that are used for storing data and search for classes and functions like:
  * Shared Preferences (Storage of key-value pairs)
  * FileOutPutStream (Using Internal or External Storage)
  * getExternal* functions (Using External Storage)
  * getWritableDatabase function (return a SQLiteDatabase for writing)
  * getReadableDatabase function (return a SQLiteDatabase for reading)
  * getCacheDir and getExternalCacheDirs function (Using cached files)

### Black-box Testing

Install and use the App as it is intended and check the following items: 

* Check the files that are shipped with the mobile application once installed in /data/data/[PackageName]/files in order to identify development, backup or simply old files that shouldn’t be in a production release. 
* Check if .db files are available, which are SQLite databases and if they contain sensitive information (usernames, passwords, keys etc.). SQlite databases can be accessed on the command line with sqlite3. 
* Check Shared Preferences that are stored as XML files in the shared_prefs directory of the App for sensitive information. 
* Check the file system permissions of the files in /data/data/[PackageName]. The permission should only allow read write and execute (rwx) to the user and his group that was created for the app (e.g. u0_a82) but not to others. Others should have no permissions to files, but may have the executable flag to directories.

These checks can either be done by logging into the Android devive via SSH to verify it or by copying all data from /data/data/[PackageName] to your local machine and verifiy it there. 


### Remediation

Do not use the external storage for sensitive data. By default, files saved to the internal storage are private to your application and other applications cannot access them (nor can the user). When the user uninstalls your application, these files are removed.
To provide additional protection for sensitive data, you might choose to encrypt local files using a key that is not directly accessible to the application. For example, a key can be placed in a KeyStore and protected with a user password that is not stored on the device. While this does not protect data from a root compromise that can monitor the user inputting the password, it can provide protection for a lost device without file system encryption.
Usage of MODE_WORLD_WRITEABLE or MODE_WORLD_READABLE should generally be avoided for files. If data needs to be shared with other applications, a content provider should be considered. A content provider offers read and write permissions to other apps and can make dynamic permission grants on a case-by-case basis. 
Different wrapper and libraries are available to add encryption to internal storage mechanisms:
* SQLCipher can be used to encrypt the SQLite database [5].
* secure-preferences can be used to encrypt the values stored within SharedPrefences [7].


### References

* [1] Using Internal Storage - http://developer.android.com/guide/topics/data/data-storage.html#filesInternal 
* [2] Using External Storage - https://developer.android.com/guide/topics/data/data-storage.html#filesExternal
* [3] Storing Data - http://developer.android.com/training/articles/security-tips.html#StoringData 
* [4] Shared Preferences - http://developer.android.com/reference/android/content/SharedPreferences.html 
* [5] SQLCipher - https://www.zetetic.net/sqlcipher/sqlcipher-for-android/ 
* [6] Android Keystore - http://developer.android.com/training/articles/keystore.html
* [7] Secure-Preferences - https://github.com/scottyab/secure-preferences 

Tools
* Enjarify - https://github.com/google/enjarify 
* JADX - https://github.com/skylot/jadx
* Dex2jar - https://github.com/pxb1988/dex2jar 
* Lint - http://developer.android.com/tools/help/lint.html 
* SQLite3 - http://www.sqlite.org/cli.html



## <a name="OMTG-DATAST-002"></a>OMTG-DATAST-002: Testing for Sensitive Data Disclosure in Log Files

There are many legit reasons to create log files on a mobile device, for example to keep track of crashes or errors that are stored locally when being offline and being sent to the application developer/company once online again or for usage statistics. However, logging sensitive data such as credit card number and session IDs might expose the data to attackers or malicious applications.
Log files can be created in various ways on each of the different operating systems. The following list shows the mechanisms that are available on Android:

* Log Class, .log[a-Z]
* Logger Class  
* StrictMode 
* System.out / System.err.print

Classification of sensitive information can vary between different industries, countries and their laws and regulations. Therefore laws and regulations need to be known that are applicable to it and to be aware of what sensitive information actually is in the context of the App. 


### OWASP Mobile Top 10
M1 - Improper Platform Usage
M2 - Insecure Data Storage

### CWE 
CWE-532 - Information Exposure Through Log Files
CWE-534 - Information Exposure Through Debug Log Files


### White-box Testing

Check the source code for usage of Logging functions, by searching for the following terms:

1. Function names like:
  * Log.d, Log.e, Log.i, Log.v. Log.w or Log.wtf
  * Logger
  * StrictMode

2. Keywords and system output to identify non-standard log mechanisms like :
  * Logfile
  * logging
  * System.out.print|System.out.println


### Black-box Testing

Use the mobile app extensively so that all functionality is at least triggered once.

1. Identify the data directory of the application in order to look for log files (/data/data/package_name). Check if log data is generated by checking the application logs, as some mobile applications create and store their own logs in the data directory.  
2. Many application developers use still System.out.println() or printStackTrace() instead of a proper logging class. Therefore the testing approach also needs to cover all output generated by the application during starting, running and closing of it and not only the output created by the log classes. In order to verify what data is written to logfiles and printed directly by using System.out.println() or printStackTrace() the code should be checked for these functions and the tool LogCat can be used to check the output. Two different approaches are available to execute LogCat. 
  * LogCat is already part of Dalvik Debug Monitor Server (DDMS) and is therefore built into Android Studio. Once the app is running and in debug mode, patterns can be defined in LogCat to reduce the log output of the app. 
  
![Log output in Android Studio](http://bb-conservation.de/sven/adb.png)
  
  
  * LogCat can be executed by using adb in order to store the log output permanently. 

```
# adb logcat > logcat.log
```


### Remediation

Ensure logging statements are removed from the production release, as logs may be interrogated or readable by other applications. Tools like ProGuard, which is already included in Android Studio or DexGuard can be used to strip out logging portions in the code when preparing the production release. For example, to remove logging calls within an android application, simply add the following option in the proguard-project.txt configuration file of Proguard:

```
-assumenosideeffects class android.util.Log
{
public static boolean isLoggable(java.lang.String, int);
public static int v(...);
public static int i(...);
public static int w(...);
public static int d(...);
public static int e(...);
}
```

### References

* Overview of Class Log - http://developer.android.com/reference/android/util/Log.html
* Debugging Logs with LogCat - http://developer.android.com/tools/debugging/debugging-log.html 

Tools
* Logcat - http://developer.android.com/tools/help/logcat.html 
* ProGuard - http://proguard.sourceforge.net/
* DexGuard - https://www.guardsquare.com/dexguard
* ClassyShark - https://github.com/google/android-classyshark 



## <a name="OMTG-DATAST-003"></a>OMTG-DATAST-003: Test that no sensitive data leaks to cloud storage

### OWASP Mobile Top 10
M[ID] - [Title]

### CWE 
CWE [ID] - [Title]

### White-box Testing

(Describe how to assess this with access to the source code and build configuration)

### Black-box Testing

[Describe how to test for this issue using static and dynamic analysis techniques. This can include everything from simply monitoring aspects of the app’s behavior to code injection, debugging, instrumentation, etc. ]

### Remediation

[Describe the best practices that developers should follow to prevent this issue]

### References

- [link to relevant how-tos, papers, etc.]




## <a name="OMTG-DATAST-004"></a>OMTG-DATAST-004: Test for sending sensitvie data to 3rd Parties

Different 3rd party services are available that can be embedded into the App to implement different features. This features can vary from tracker services to monitor the user behaviour within the App, selling banner advertisements or to create a better user experience. Interacting with these services abstracts the complexity and neediness to implement the functionality on it’s own and to reinvent the wheel. 
The downside is that a developer doesn’t know in detail what code is executed via 3rd party libraries and therefore giving up visibility. Consequently it should be ensured that not more information as needed is sent to the service and that no sensitive information is disclosed. 
3rd party services are mostly implemented in two ways:
* By using a standalone library, like a Jar in an Android project that is getting included into the APK.
* By using a full SDK.


### OWASP Mobile Top 10
M7 - Client Code Quality

### CWE 
CWE 359 - Exposure of Private Information ('Privacy Violation')


### White-box Testing

Some 3rd party libraries can be automatically integrated into the App through a wizard within the IDE. The permissions set in the AnroidManifest.xml  when installing a library through an IDE wizard should be reviewed. Especially permissions to access SMS (READ_SMS), contacts (ROAD_CONTACTS) or the location (ACCESS_FINE_LOCATION) should be challenged if they are really needed to make the library work at a bare minimum, see also OMTG-ENV-XXX. When talking to developers it should be shared to them that it’s actually necessary to have a look at the diff on the project source code before and after the library was installed through the IDE and what changes have been made to the code base. 

The source code should be checked for API calls or functions provided by the 3rd party library.

### Black-box Testing

All requests made  to the external service should be analyzed if any sensitive information is embedded into them. 
Dynamic analysis can be performed launching a MITM attack using Burp Proxy, to intercept the traffic exchanged between client and server. Using the certificate provided by Portswigger, Burp can intercept and decrypt the traffic on the fly and manipulate it as you prefer. First of all we need to setup Burp, on our laptop, to listen on a specific port from all the interfaces. After that we can setup the Android device to redirect all the traffic to our laptop, i.e. setting our laptop IP address like proxy.
A complete guide can be found here (https://support.portswigger.net/customer/portal/articles/1841101-configuring-an-android-device-to-work-with-burp)
Once we are able to route the traffic to burp, we can try to sniff the traffic from the application. When using the App all requests that are not going directly to the server where the main function is hosted should be checked, if any sensitive information is sent to a 3rd party. This could be for example PII in a tracker or ad service. 
When decompiling the App, API calls and/or functions provided through the 3rd party library should be reviewed on a source code level to identify if they are used accordingly to best practices. 
The Jar files loaded into the project should be reviewed in order to identify with the developers if they are needed and also if they are out of date and contain known vulnerabilities.

### Remediation

All data that is sent to 3rd Party services should be anonymized, so no PII data is available. Also all other data, like IDs in an application that can be mapped to a user account or session should not be sent to a third party.  
AndroidManifest.xml should only contain the permissions that are absolutely needed to work properly and as intended.

### References

* Bulletproof Android, Godfrey Nolan, Chapter 7 - Third-Party Library Integration


## <a name="OMTG-DATAST-005"></a>OMTG-DATAST-005: Test that keyboard cache is disabled for sensitive data

### OWASP Mobile Top 10
M[ID] - [Title]

### CWE 
CWE [ID] - [Title]

### White-box Testing

(Describe how to assess this with access to the source code and build configuration)

### Black-box Testing

[Describe how to test for this issue using static and dynamic analysis techniques. This can include everything from simply monitoring aspects of the app’s behavior to code injection, debugging, instrumentation, etc. ]

### Remediation

[Describe the best practices that developers should follow to prevent this issue]

### References

- [link to relevant how-tos, papers, etc.]


## <a name="OMTG-DATAST-006"></a>OMTG-DATAST-006: Test that clipboard is deactivated for sensitive input fields

### OWASP Mobile Top 10
M[ID] - [Title]

### CWE 
CWE [ID] - [Title]

### White-box Testing

(Describe how to assess this with access to the source code and build configuration)

### Black-box Testing

[Describe how to test for this issue using static and dynamic analysis techniques. This can include everything from simply monitoring aspects of the app’s behavior to code injection, debugging, instrumentation, etc. ]

### Remediation

[Describe the best practices that developers should follow to prevent this issue]

### References

- [link to relevant how-tos, papers, etc.]



## <a name="OMTG-DATAST-007"></a>OMTG-DATAST-007: Test that no sensitive data is exposed via IPC mechanisms

### OWASP Mobile Top 10
M[ID] - [Title]

### CWE 
CWE [ID] - [Title]

### White-box Testing

(Describe how to assess this with access to the source code and build configuration)

### Black-box Testing

[Describe how to test for this issue using static and dynamic analysis techniques. This can include everything from simply monitoring aspects of the app’s behavior to code injection, debugging, instrumentation, etc. ]

### Remediation

[Describe the best practices that developers should follow to prevent this issue]

### References

- [link to relevant how-tos, papers, etc.]



## <a name="OMTG-DATAST-009"></a>OMTG-DATAST-009: Test for Sensitive Data in Backups

### OWASP Mobile Top 10
M2 - Insecure Data Storage

### CWE 
CWE 530 - https://cwe.mitre.org/data/definitions/530.html

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

Extract the tar file into your current working directory to perform your analysis for sensitive data.

```
$ tar xvf mybackup.tar
```

### Remediation

To prevent backing up the app's data, set the android:allowBackup attribute must be set to false in AndroidManifest.xml.

### References

- Documentation for the Application tag: https://developer.android.com/guide/topics/manifest/application-element.html#allowbackup




## <a name="OMTG-DATAST-009"></a>OMTG-DATAST-009: Test that no sensitive data leaks through backups

### OWASP Mobile Top 10
M[ID] - [Title]

### CWE 
CWE [ID] - [Title]

### White-box Testing

(Describe how to assess this with access to the source code and build configuration)

### Black-box Testing

[Describe how to test for this issue using static and dynamic analysis techniques. This can include everything from simply monitoring aspects of the app’s behavior to code injection, debugging, instrumentation, etc. ]

### Remediation

[Describe the best practices that developers should follow to prevent this issue]

### References

- [link to relevant how-tos, papers, etc.]


## <a name="OMTG-DATAST-010"></a>OMTG-DATAST-010: Test that no sensitive data leaks when backgrounded

### OWASP Mobile Top 10
M[ID] - [Title]

### CWE 
CWE [ID] - [Title]

### White-box Testing

(Describe how to assess this with access to the source code and build configuration)

### Black-box Testing

[Describe how to test for this issue using static and dynamic analysis techniques. This can include everything from simply monitoring aspects of the app’s behavior to code injection, debugging, instrumentation, etc. ]

### Remediation

[Describe the best practices that developers should follow to prevent this issue]

### References

- [link to relevant how-tos, papers, etc.]



## <a name="OMTG-DATAST-011"></a>OMTG-DATAST-011: Test for Sensitive Data Disclosure in Process Memory

Analyzing the memory can help to identify the root cause of different problems, like for example why an application is crashing, but can also be used to identify sensitive data. This section describes how to check for sensitive data and disclosure of data in general within the process memory. 

To be able to investigate the memory of an application a memory dump needs to be created first or the memory needs to be viewed with real-time updates. This is also already the problem, as the application only stores certain information in memory if certain functions are triggered within the application. Memory investigation can of course be executed randomly in every stage of the application, but it is much more beneficial to understand first what the mobile application is doing and what kind of functionalities it offers and also make a deep dive into the decompiled code before making any memory analysis. 
Once sensitive functions are identified (like decryption of data) the investigation of a memory dump might be beneficial in order to identify sensitive data like a key or decrypted information. 

### OWASP Mobile Top 10
TBD

### CWE 
CWE-316 - Cleartext Storage of Sensitive Information in Memory

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

### OWASP Mobile Top 10
M[ID] - [Title]

### CWE 
CWE [ID] - [Title]

### White-box Testing

(Describe how to assess this with access to the source code and build configuration)

### Black-box Testing

[Describe how to test for this issue using static and dynamic analysis techniques. This can include everything from simply monitoring aspects of the app’s behavior to code injection, debugging, instrumentation, etc. ]

### Remediation

[Describe the best practices that developers should follow to prevent this issue]

### References

- [link to relevant how-tos, papers, etc.]



## <a name="OMTG-DATAST-013"></a>OMTG-DATAST-013: Test remote locking and wiping

### OWASP Mobile Top 10
M[ID] - [Title]

### CWE 
CWE [ID] - [Title]

### White-box Testing

(Describe how to assess this with access to the source code and build configuration)

### Black-box Testing

[Describe how to test for this issue using static and dynamic analysis techniques. This can include everything from simply monitoring aspects of the app’s behavior to code injection, debugging, instrumentation, etc. ]

### Remediation

[Describe the best practices that developers should follow to prevent this issue]

### References

- [link to relevant how-tos, papers, etc.]
