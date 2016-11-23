## <a name="OMTG-DATAST-001"></a>OMTG-DATAST-002: Testing for Insecure Storage of Credentials and Keys 

## <a name="OMTG-DATAST-002"></a>OMTG-DATAST-002: Testing for Sensitive Data Disclosure in Log Files


### Black-box Testing

[Describe how to test for this issue using static and dynamic analysis techniques. This can include everything from simply monitoring aspects of the app’s behavior to code injection, debugging, instrumentation, etc. ]

### White-box Testing

Check the source code for usage of predefined/custom Logging statements using the following keywords :
* For predefined and built-in functions :
  * NSLog
  * NSAssert
  * NSCAssert
  * fprintf
* For custom functions :
  * Logging
  * Logfile



### Remediation

Use a define to enable NSLog statements for development and debugging, and disable these before shipping the software. This can be done by putting the following code into the appropriate PREFIX_HEADER (*.pch) file:

```C#
#ifdef DEBUG
#   define NSLog (...) NSLog(__VA_ARGS__)
#else
#   define NSLog (...)
#endif
```

### References

- [link to relevant how-tos, papers, etc.]


## <a name="OMTG-DATAST-010"></a>OMTG-DATAST-010: Test that no sensitive data leaks when backgrounded


### Black-box Testing

[Describe how to test for this issue using static and dynamic analysis techniques. This can include everything from simply monitoring aspects of the app’s behavior to code injection, debugging, instrumentation, etc. ]

### White-box Testing

While analyzing the source code, look for the fields or screens where sensitive data is involved. Identify if the application sanitize the screen before being backgrounded.

### Remediation

The application must obsucate/hide any sensitive informations before being backgrouded, either by bluring the screen (e.g. using GPUImageiOSBlurFilter) or overriding the current view in the applicationDidEnterBackground state transition method.


### References

Proceed to a page on the application which displays sensitive information such as username, email address, account details, etc. Background the application by hitting the Home button on your iOS device. SSH into your iOS device and proceed to the following directory:
/var/mobile/Containers/Data/Application/$APP_ID/Library/Caches/Snapshots/

Depending on your iOS version, the start of the directory (/var/mobile) might be different, the test was conducted on a iOS 8.1 device.

If the application caches the sensitive information page as a screenshot, it fails this test.

It is highly recommended to have a default screenshot that will be cached whenever the application enters background.



