### <a name="OMTG-DATAST-002"></a>OMTG-DATAST-002: Test for Sensitive Data Disclosure in Log Files

#### Overview

There are many legit reasons to create log files on a mobile device, for example to keep track of crashes or errors that are stored locally when being offline and being sent to the application developer/company once online again or for usage statistics. However, logging sensitive data such as credit card number and session IDs might expose the data to attackers or malicious applications.
Log files can be created in various ways on each of the different operating systems. The following list shows the mechanisms that are available on iOS:

* NSLog Method 
* printf-like function
* NSAssert-like function
* Macro

Classification of sensitive information can vary between different industries, countries and their laws and regulations. Therefore laws and regulations need to be known that are applicable to it and to be aware of what sensitive information actually is in the context of the App.

#### Black-box Testing

[Describe how to test for this issue using static and dynamic analysis techniques. This can include everything from simply monitoring aspects of the app’s behavior to code injection, debugging, instrumentation, etc. ]

#### White-box Testing

Check the source code for usage of predefined/custom Logging statements using the following keywords :
* For predefined and built-in functions :
  * NSLog
  * NSAssert
  * NSCAssert
  * fprintf
* For custom functions :
  * Logging
  * Logfile


#### Remediation

Use a define to enable NSLog statements for development and debugging, and disable these before shipping the software. This can be done by putting the following code into the appropriate PREFIX_HEADER (*.pch) file:

```C#
#ifdef DEBUG
#   define NSLog (...) NSLog(__VA_ARGS__)
#else
#   define NSLog (...)
#endif
```

#### References

- [link to relevant how-tos, papers, etc.]


### <a name="OMTG-DATAST-010"></a>OMTG-DATAST-010: Test for Sensitive Data in the Backgrounded App

#### Overview

Manufacturers want to provide device users an aesthetically pleasing effect when an application is entered or exited, hence they introduced the concept of saving a screenshot when the application goes into the background. This feature could potentially pose a security risk for an application, as the screenshot containing sensitive information (e.g. a screenshot of an email or corporate documents) is written to local storage, where it is recovered either by a rogue application on a jailbroken device, or by someone who steals the device.

#### Black-box Testing

[Describe how to test for this issue using static and dynamic analysis techniques. This can include everything from simply monitoring aspects of the app’s behavior to code injection, debugging, instrumentation, etc. ]

#### White-box Testing

While analyzing the source code, look for the fields or screens where sensitive data is involved. Identify if the application sanitize the screen before being backgrounded.

#### Remediation

The application must obsucate/hide any sensitive informations before being backgrouded, either by bluring the screen (e.g. using GPUImageiOSBlurFilter) or overriding the current view in the applicationDidEnterBackground state transition method.

#### References

- [link to relevant how-tos, papers, etc.]
