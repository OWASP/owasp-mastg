## <a name="OMTG-DATAST-001"></a>OMTG-DATAST-001: Test for Insecure Storage of Credentials and Keys

An app shouldn’t store any sensitive information like credentials, passwords or encryption keys (even when using security controls and mechanisms offered by the OS as a best practice to protect this information). It should be remembered that the confidentiality of sensitive information stored locally on a device cannot be guaranteed, and that most controls can be bypassed on a rooted device.
In case sensitive information needs to be stored, several best practices available on the OS level should be applied to make it harder for attackers to retrieve these information. 

### White-box Testing

When going through the source code it should be analyzed if native mechanisms that are offered by Android are applied to the identified sensitive information. Sensitive information should not be stored in clear text and should be encrypted. Especially encryption operations should rely on solid and tested functions provided by the SDK. The following describes different “bad practices” that should be avoided:
* Check if simple bit operations are used, like XOR or Bit flipping to “encrypt” sensitive information like credentials or private keys that are stored locally. This should be avoided as the data can easily be recovered. 
* Check if keys are created or used without taking advantage of the Android onboard features like the KeyStore. 
* See also OMTG-DATAST-004 to identify what kind of information is stored persistently and if credentials or keys are disclosed.

The code should also be analysed if sensitive data is used properly and securely:
* Sensitive information should not be stored for too long in the RAM (see also “Testing for Sensitive Data Disclosure in Process Memory (OMTG-DATAST-006)”).
* Set variables that use sensitive information to null once finished. 
* Use immutable objects for sensitive data so it cannot be changed.

If sensitive information needs to be stored on the device itself, several functions/API calls are available to protect the data on the Android device by using the KeyChain and Keystore. The following best practices should therefore be used:
* Check if a key pair is created within the App by looking for the class KeyPairGenerator.
* Check that the application is using the KeyStore and Cipher mechanisms to securely store encrypted information on the device. Look for the pattern “import java.security.KeyStore" and “import javax.crypto.Cipher” and it’s usage. Encryption or decryption functions that were self implemented need to be avoided.   
* The store(OutputStream stream, char[] password) function can be used to store the KeyStore to disk with a specified password. Check that the password provided is not hardcoded and is defined by user input as this should only be known to the user. Look for the pattern “.store(“.



### Black-box Testing

For black box testing, the memory should be analysed in order to be able to retrieve sensitive information, like private keys related to the encryption process. See also OMTG-DATAST-007.
Check if keys or credentials are logged in log files (OMTG-DATAST-002) or stored permanently unencrypted in the file system (OMTG-DATAST-004). 


### Remediation

The following tasks should be done:
* Identify keys and passwords in the App, e.g. entered by the users, sent back by the endpoint, shipped within the App and how this sensitive data is processed locally. 
* Decide (with the developers) if this sensitive stored information locally is needed, and if not if it can be removed or relocated to the endpoint. 

If sensitive information is needed locally on the device several best practices are offered by Android and iOS that should be used to store data securely instead of reinventing the wheel or leave it unencrypted on the device. 
Username and password should not be stored on the device. Instead, perform initial authentication using the username and password supplied by the user, and then use a short-lived, service-specific authorization token (session token).
If credentials, keys or other sensitive information need to be stored locally and are only used by one application on the device use the KeyStore to create a keypair and use it for encrypting the information. 
As a security in depth measure code obfuscation should also be applied to the App, to make reverse engineering harder for attackers. 
The following is a list of best practice functions used for secure storage of certificates and keys:
 
* KeyStore [3]: The KeyStore provides a secure system level credential storage. It is important to note that the credentials are not actually stored within the KeyStore. An app can create a new private/public key pair to encrypt application secrets by using the public key and decrypt the same by using the private key. The KeyStores is a secure container that makes it difficult for an attacker to retrieve the private key and guards the encrypted data. Nevertheless an attacker can access all keys on a rooted device in the folder /data/misc/keystore/. 	Although the Android Keystore provider was introduced in API level 18 (Android 4.3), the Keystore itself has been available since API 1, restricted to use by VPN and WiFi systems. The Keystore is encrypted using the user’s own lockscreen pin/password, hence, when the device screen is locked the Keystore is unavailable [1].	
* KeyChain [2]: The KeyChain class is used to store and retrieve private keys and their corresponding certificate (chain). The user will be prompted to set a lock screen PIN or password to protect the credential storage if it hasn’t been set, if something gets imported into the KeyChain the first time.


### References

[1] How to use the Android Keystore to store passwords and other sensitive information  - http://www.androidauthority.com/use-android-keystore-store-passwords-sensitive-information-623779/
[2] Android KeyChain - http://developer.android.com/reference/android/security/KeyChain.html 
[3] Android KeyStore System - http://developer.android.com/training/articles/keystore.html



## <a name="OMTG-DATAST-001"></a>OMTG-DATAST-002: Testing for Sensitive Data Disclosure in Log Files

There are many legit reasons to create log files on a mobile device, for example to keep track of crashes or errors that are stored locally when being offline and being sent to the application developer/company once online again or for usage statistics. However, logging sensitive data such as credit card number and session IDs might expose the data to attackers or malicious applications.
Log files can be created in various ways on each of the different operating systems. The following table shows the mechanisms that are available on each platform:

| iOS        | Android       | 
| ------------- |-------------| 
| NSLog Method      | Log Class, .log[a-Z] | 
| printf-like function      | Logger Class      |
| NSAssert-like function | StrictMode     |
| Macro | System.out / System.err.print    |

### OWASP Mobile Top 10
M1 - Improper Platform Usage
M2 - Insecure Data Storage

### CWE 
CWE-532 - Information Exposure Through Log Files
CWE-534 - Information Exposure Through Debug Log Files


### White-box Testing

Check the source code for usage of Logging functions. 

1. Decompile the APK to get access to the Java source code as described in <link to guide>
2. Import the Java files in an IDE (e.g. IntelliJ or Eclipse) or Editor of your choice or directly open them in JD-Gui, ClassyShark or use grep on the command line to search for
* functions like:
..* Log.d, Log.e, Log.i, Log.v. Log.w or Log.wtf
..* Logger
..* System.out.print|System.out.println
..* StrictMode
* Keywords (to identify non-standard log mechanisms) like :
..* Logfile
..* logging



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

Extract the tar file into your current working directory to perform your analysis for sensitive data.

```
$ tar xvf mybackup.tar
```

### Remediation

To prevent backing up the app's data, set the android:allowBackup attribute must be set to false in AndroidManifest.xml.

### References

- Documentation for the Application tag: https://developer.android.com/guide/topics/manifest/application-element.html#allowbackup

