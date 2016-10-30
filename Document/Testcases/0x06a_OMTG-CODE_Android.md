## <a name="OMTG-CODE-001"></a>OMTG-CODE-001: Testing for Debug Build

### White-box Testing

1. Check the AndroidManifest.xml for the value of "android:debuggable" attribute within the application element. This setting specifies whether or not the application can be debugged, even when running on a device in user mode. A value of "true" if it can be, And "false" if not. The default value is "false". If the debuggable flag is set and activated, the app can be debugged. A comprehensive guide to debug an Android application can be found within the official documentation by Android (see references).

2.	Check the source code for patterns like "startMethodTracing|stopMethodTracing”.


### Black-box Testing

Using a debugger to manipulate application variables at runtime can be a powerful technique to employ while penetration testing Android applications. Android applications can be unpacked, modified, re-assembled, and converted to gain access to the underlying application code, however understanding which variables are important and should be modified is a whole other story that can be laborious and time consuming. <Give detailed explanation how to do it>

### Remediation

For production releases, the attribute android:debuggable must be set to false within the application element. This ensures that a debugger cannot attach to the process of the application.

### References

* Configuring your application for release - http://developer.android.com/tools/publishing/preparing.html#publishing-configure 
* Debugging with Android Studio - http://developer.android.com/tools/debugging/debugging-studio.html

