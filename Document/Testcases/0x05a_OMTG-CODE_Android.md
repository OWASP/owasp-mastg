## <a name="OMTG-CODE-001"></a>OMTG-CODE-001: Testing for Debug Build

### White-box Testing

Check the AndroidManifest.xml for the value of "android:debuggable" attribute within the application element :

```xml
<?xml version="1.0" encoding="utf-8" standalone="no"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.android.owasp">
    
    ...
    
    <application android:allowBackup="true" android:debuggable="true" android:icon="@drawable/ic_launcher" android:label="@string/app_name" android:theme="@style/AppTheme">
        <meta-data android:name="com.owasp.main" android:value=".Hook"/>
    </application>
</manifest>
```

This setting specifies whether or not the application can be debugged, even when running on a device in user mode. A value of "true" if it can be, And "false" if not. The default value is "false".

A comprehensive guide to debug an Android application can be found within the official documentation by Android (see references).



### Black-box Testing

When targetting a compiled Android application, the most reliable method is to first decompile it in order to obtain the AndroidManifest.xml file (see Decompiling Android App Guide - #TODO-Create a general guide that can bee referenced anywhere in the OMSTF) and check the value of "android:debuggable" attribute.

Otherwise, use the Android Asset Packaging Tool (aapt) to check the debuggable flag :

```
$ aapt l -a /path/to/apk/file.apk | grep debuggable
```

Will return the following if android:debuggable parameter is set to true :

```
      A: android:debuggable(0x0101000f)=(type 0x12)0xffffffff
```

### Remediation

For production releases, the attribute android:debuggable must be set to false within the application element. This ensures that a debugger cannot attach to the process of the application.

### References

* Configuring your application for release - http://developer.android.com/tools/publishing/preparing.html#publishing-configure 
* Debugging with Android Studio - http://developer.android.com/tools/debugging/debugging-studio.html

## <a name="OMTG-CODE-002"></a>OMTG-CODE-002: Testing for Exception Handling

### White-box Testing

Review the source code to understand/identify who the application handle various types of errors (IPC communications, remote services invokation, etc). Here are some examples of the checks to be performed at this stage :

* Verify that the application use a [well-designed] (https://www.securecoding.cert.org/confluence/pages/viewpage.action?pageId=18581047) (an unified) scheme to handle exceptions.
* Verify that the application doesn't expose sensitive information while handeling exceptions, but are still verbose enough to explain the issue to the user. 
* C3

### Black-box Testing

[Describe how to test for this issue using static and dynamic analysis techniques. This can include everything from simply monitoring aspects of the app’s behavior to code injection, debugging, instrumentation, etc. ]

### Remediation

[Describe the best practices that developers should follow to prevent this issue]

### References

- [link to relevant how-tos, papers, etc.]

## <a name="OMTG-CODE-003"></a>OMTG-CODE-003: Testing for Secure Compiler Flags

Since most Android applications are Java based, they are [immunue](https://www.owasp.org/index.php/Reviewing_Code_for_Buffer_Overruns_and_Overflows#.NET_.26_Java) to buffer overflow vulnerabilities.


## <a name="OMTG-CODE-004"></a>OMTG-CODE-004: Testing for Unreacheble/Dead code

### White-box Testing

(Describe how to assess this with access to the source code and build configuration)

### Black-box Testing

[Describe how to test for this issue using static and dynamic analysis techniques. This can include everything from simply monitoring aspects of the app’s behavior to code injection, debugging, instrumentation, etc. ]

### Remediation

Some best practices to consider to securely handle exception within a mobile application :

### References

- [link to relevant how-tos, papers, etc.]
