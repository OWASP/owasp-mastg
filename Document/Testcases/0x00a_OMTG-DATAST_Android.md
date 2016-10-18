## <a name="OMTG-DATAST-001"></a>OMTG-DATAST-001: Test that system credential storage facilities are used appropriately to store sensitive data, such as user credentials or cryptographic keys.

### White-box Testing

- Files with permissions of MODE_WORLD_READABLE or MODE_WORLD_WRITABLE are accessible even though it is stored in the app’s private data directory. WRITE_EXTERNAL_STORAGE or READ_EXTERNAL_STORAGE app permission allows access to the external phone storage which is world readable.

        egrep -irn "MODE_WORLD_READABLE|MODE_WORLD_WRITABLE|WRITE_EXTERNAL_STORAGE|READ_EXTERNAL_STORAGE" . 

- Below listed functions read from or write to the internal app directory.

        egrep -irn "openFileOutput(|createTempFile(|openFile(|getFilesDir(|getCacheDir(" . 
        
-  getExternalFilesDir() and getExternalFilesDirs() will create directory on the external storage. Files created in those directories can be only read by the app itself. getExternalStoragePublicDirectory() will create a directory that is world rw.

        egrep -irn "getExternalStoragePublicDirectory(|getExternalFilesDir(|getExternalFilesDirs(" . 


### Black-box Testing

 1. Use the mobile app extensively so that all functionality is at least triggered once.
  
 2. Download the mobile app data directory from  /data/data/com.example.appname and the global storage directory /sdcard/ . 
 
 3. Look for sensitive data such as credentials, passwords, usernames, encryption keys or any other information that could be classified as sensitive in all downloaded files. 

### Remediation

Sensitive information should not be stored on the device. Instead, perform initial authentication using credentials supplied by the user, and then use a short-lived, service-specific authorization token (session token).
If credentials, keys or other sensitive information need to be stored locally use the KeyChain or KeyStore according to your requirements.

- KeyChain: Use the KeyChain API when you want system-wide credentials. When an app requests the use of any credential through the KeyChain API, users get to choose, through a system-provided UI, which of the installed credentials an app can access. This allows several apps to use the same set of credentials with user consent.

- Keystore: Use the Android Keystore provider to let an individual app store its own credentials that only the app itself can access. This provides a way for apps to manage credentials that are usable only by itself while providing the same security benefits that the KeyChain API provides for system-wide credentials. This method requires no user interaction to select the credentials.

### References

[OWASP Mobile TOP 10: Insecure Data Storage](https://www.owasp.org/index.php/Mobile_Top_10_2014-M2)

[Android KeyChain Documentation](http://developer.android.com/reference/android/security/KeyChain.html)

[Android KeyStore System Documentation](http://developer.android.com/training/articles/keystore.html)

[Android Storage Documentation](https://developer.android.com/training/basics/data-storage/index.html)

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

