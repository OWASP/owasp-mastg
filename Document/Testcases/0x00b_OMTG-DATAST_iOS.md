## <a name="OMTG-DATAST-001-1"></a>OMTG-DATAST-001-1: Test for system credentials storage features 

### Black-box Testing

A way to identify if sensitive information like credentials and keys are stored insecurely and without leveraging the native functions from IOS is to analyse the app data directory. It is important to trigger as much app functionality as possbile before the data is analysed, as the app might only store system credentials as specific functionality is triggered by the user. A static analysis can then be performed for the data dump based on generic keywords and app specifc data. Identify how the application stores data locally on the iOS device. Some of the possible options for the application to store it's data locally includes:
 
- Plain Files
- Plist
- SQLite3 DB
- Realm DB

Steps :

1. Proceed to trigger functionality that stores potential sensitive data.
2. SSH into your iOS device and browse to the following directory: `/var/mobile/Containers/Data/Application/$APP_ID/`
3. Perform a grep command of the data that you have stored, such as: `grep -irn "jk@vantagepoint.sg"`.
4. If the sensitive data is being stored in plaintext, it fails this test.

Manual dynamic analysis such as debugging can also be leveraged to verify how specific system credentials are stored and processed on the device. As this approach is more time consuming and is likely conducted manually, it might be only feasible for specific use cases.  


### White-box Testing
When going through the source code it should be analyzed if native mechanisms that are offered by IOS are applied to the identified sensitive information. Ideally sensitive information should not be stored on the device at all. If there is a requirement to store sensitive information on the device itself, several functions/API calls are available to protect the data on IOS device by using for example the Keychain. 

### Remediation
If sensitive information (credentials, keys, PII, etc.) is needed locally on the device several best practices are offered by IOS that should be used to store data securely instead of reinventing the wheel or leave it unencrypted on the device.

The following is a list of best practice used for secure storage of certificates and keys and sensitve data in general:
- For small amounts of sensitive data such as credentials or keys use the [Keychain Services](https://developer.apple.com/reference/security/1658642-keychain_services?language=objc) to securely store it locally on the device. Keychain data is protected using a class structure similar to the one used in file Data Protection. These classes have behaviors equivalent to file Data Protection classes, but use distinct keys and are part of APIs that are named differently. The the default behaviour is `kSecAttrAccessibleWhenUnlocked`. For more information have a look at the available modes [Keychain Item Accessibility](https://developer.apple.com/reference/security/1658642-keychain_services/1663541-keychain_item_accessibility_cons).
- Cryptographic functions that have been self implemented to encryt or decrypt local files should be avoided.  
- Avoid insecure storage functions for sensitive information such as credentials and keys as illustrated in chapter OMTG-DATAST-001-2.   


### References

* [Keychain Services Programming Guide](https://developer.apple.com/library/content/documentation/Security/Conceptual/keychainServConcepts/iPhoneTasks/iPhoneTasks.html)
* [IOS Security Guide](https://www.apple.com/business/docs/iOS_Security_Guide.pdf)


## <a name="OMTG-DATAST-001-2"></a>OMTG-DATAST-001-2: Test for Sensitive Data Disclosure in Local Storage


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

* [https://developer.apple.com/library/content/documentation/Security/Conceptual/keychainServConcepts/iPhoneTasks/iPhoneTasks.html] - Keychain Services Programming Guide
* [Android KeyStore][19149717]


## <a name="OMTG-DATAST-005"></a>OMTG-DATAST-005: Test that keyboard cache is disabled for sensitive data


### Black-box Testing

Reset your iOS device keyboard cache by going through:

Settings > General > Reset > Reset Keyboard Dictionary

Proceed to use the application's functionalities. Identify the functions which allow users to enter sensitive data.

Dump the keyboard cache file dynamic-text.dat at the following directory:
/private/var/mobile/Library/Keyboard/

Look for sensitive data such as username, email addresses, credit card numbers, etc.
If the sensitive data can be obtained through the keyboard cache file, it fails this test.

### White-box Testing

[Describe how to test for this issue using static and dynamic analysis techniques. This can include everything from simply monitoring aspects of the app’s behavior to code injection, debugging, instrumentation, etc. ]

### Remediation

The application must ensure that data typed into text fields which contains sensitive information must not be cached. This can be achieved by disabling the feature programmatically by using the AutoCorrection = FALSE directive in the desired UITextFields. For data that should be masked such as PIN and passwords, set the textField.secureTextEntry to YES.

### References

- [link to relevant how-tos, papers, etc.]


## <a name="OMTG-DATAST-010"></a>OMTG-DATAST-010: Test that no sensitive data leaks when backgrounded


### Black-box Testing

Proceed to a page on the application which displays sensitive information such as username, email address, account details, etc. Background the application by hitting the Home button on your iOS device. SSH into your iOS device and proceed to the following directory:
/var/mobile/Containers/Data/Application/$APP_ID/Library/Caches/Snapshots/

Depending on your iOS version, the start of the directory (/var/mobile) might be different, the test was conducted on a iOS 8.1 device.

If the application caches the sensitive information page as a screenshot, it fails this test.

It is highly recommended to have a default screenshot that will be cached whenever the application enters background.

### White-box Testing

While analyzing the source code, look for the fields or screens where sensitive data is involved. Identify if the application sanitize the screen before being backgrounded.

### Remediation

The application must obsucate/hide any sensitive informations before being backgrouded, either by bluring the screen (e.g. using GPUImageiOSBlurFilter) or overriding the current view in the applicationDidEnterBackground state transition method.

### References

- [link to relevant how-tos, papers, etc.]
