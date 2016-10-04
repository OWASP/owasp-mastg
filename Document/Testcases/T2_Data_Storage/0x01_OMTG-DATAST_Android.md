## <a name="OMTG-DATAST-001"></a>OMTG-DATAST-001: Test Sensitive Data Storage

### White-box Testing

(Describe how to assess this with access to the source code and build configuration)

### Black-box Testing

[Describe how to test for this issue using static and dynamic analysis techniques. This can include everything from simply monitoring aspects of the app’s behavior to code injection, debugging, instrumentation, etc. ]

### Remediation

[Describe the best practices that developers should follow to prevent this issue]

### References

- [link to relevant how-tos, papers, etc.]

## <a name="OMTG-DATAST-001"></a>OMTG-DATAST-009: Test for Sensitive Data in Backups

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

