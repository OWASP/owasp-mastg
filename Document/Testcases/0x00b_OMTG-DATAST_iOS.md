## <a name="OMTG-DATAST-001"></a>OMTG-DATAST-001: Testing for Insecure Storage of Credentials and Keys 

### Black-box Testing

[Describe how to test for this issue using static and dynamic analysis techniques. This can include everything from simply monitoring aspects of the app’s behavior to code injection, debugging, instrumentation, etc. ]

Identify how the application stores data locally on the iOS device.
Some of the possible options for the application to store it's data locally includes:
- Plist
- SQLite3 DB
- Realm DB

Proceed to store some data by using the application functionalites. SSH into your iOS device and browse to the following directory: /var/mobile/Containers/Data/Application/$APP_ID/

Perform a grep command of the data that you have stored, such as:
grep -irn "jk@vantagepoint.sg" .

If the data is being stored in plaintext, it fails this test.

### White-box Testing

[Describe how to test for this issue using static and dynamic analysis techniques. This can include everything from simply monitoring aspects of the app’s behavior to code injection, debugging, instrumentation, etc. ]

Determine how the application stores data locally in the source code.
Look for the following strings in the source code.

For .plist storage:
- NSString* plistPath
- writeToPath:plistPath
- :@"\*.plist"

For SQLite3 storage:
- sqlite3_stmt (preparing sqlite3 statement)
- sqlite3_step (executing sqlite3 statement)

Look for the specific kind of data that is being stored locally and determine if it is sensitive data.


### Remediation

If the application has to store data locally on the device, ensure that proper encryption is implemented for the sensitive data.


### References

 - [link to relevant how-tos, papers, etc.]


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


## <a name="OMTG-DATAST-005"></a>OMTG-DATAST-005: Test that keyboard cache is disabled for sensitive data


### Black-box Testing

Follow these steps to retrieve the keyboard cache:

1. Reset your iOS device keyboard cache by going through:
2. Settings > General > Reset > Reset Keyboard Dictionary
3. Proceed to use the application's functionalities. Identify the functions which allow users to enter sensitive data.
4. Dump the keyboard cache file dynamic-text.dat at the following directory: /private/var/mobile/Library/Keyboard/
5. Look for sensitive data such as username, email addresses, credit card numbers, etc.If the sensitive data can be obtained through the keyboard cache file, it fails this test.

### White-box Testing

[Describe how to test for this issue using static and dynamic analysis techniques. This can include everything from simply monitoring aspects of the app’s behavior to code injection, debugging, instrumentation, etc. ]

Look for sensitive input fields such as email addresses, usernames, passwords, credit card numbers, etc.

For fields that require masked output such as password, check if the text field secureTextEntry is set to True:
- textField.secureTextEntry = TRUE;

For fields that are considered sensitive data, ensure that autocorrectionType is set to False:
- textField.autocorrectionType = FALSE; // or use  UITextAutocorrectionTypeNo

By default, all text fields will have auto correction enabled and it will be automatically cached into the keyboard dynamic text file.

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

Check for implementations such as:
- applicationWillResignActive:
- applicationDidBecomeActive:
- applicationDidEnterBackground:

If no such implementations or similar implementations exist, the application will most probably cache the current page when being backgrounded.

### Remediation

The application must obsucate/hide any sensitive informations before being backgrouded, either by bluring the screen (e.g. using GPUImageiOSBlurFilter) or overriding the current view in the applicationDidEnterBackground state transition method.

### References

- [link to relevant how-tos, papers, etc.]
- http://stackoverflow.com/questions/27265957/ios-takes-a-screenshot-of-app-every-time-it-is-sent-to-the-background-how-woul



