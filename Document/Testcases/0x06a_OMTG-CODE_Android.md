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

Use the Android Asset Packaging Tool (aapt) to check the debuggable flag :

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

