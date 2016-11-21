## <a name="OMTG-DATAST-001-1"></a>OMTG-DATAST-001-1: Test for system credentials storage features 

### Black-box Testing

A way to identify if sensitive information like credentials and keys are stored insecurely and without leveraging the native functions from IOS is to analyse the app data directory. It is important to trigger as much app functionality as possbile before the data is analysed, as the app might only store system credentials as specific functionality is triggered by the user. A static analysis can then be performed for the data dump based on generic keywords and app specifc data.

Manual dynamic analysis such as debugging can also be leveraged to verify how specific system credentials are stored and processed on the device. As this approach is more time consuming and is likely conducted manually, it might be only feasible for specific use cases.  

### White-box Testing
When going through the source code it should be analyzed if native mechanisms that are offered by IOS are applied to the identified sensitive information. Ideally sensitive information should not be stored on the device at all. If there is a requirement to store sensitive information on the device itself, several functions/API calls are available to protect the data on IOS device by using the KeyChain and Keystore. The following controls should therefore be used:


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

- [link to relevant how-tos, papers, etc.]
