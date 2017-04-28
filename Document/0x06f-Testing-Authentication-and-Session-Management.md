## Testing Authentication

### Verify that Users Are Properly Authenticated

It is important to clarify that this control is at the server side, so the testing will be the same for iOS and Android applications. Please look at "Verify that Users Are Properly Authenticated" in Android for a detailed explanation of this test case.

### Testing Session Management

It is important to clarify that this control is at the server side, so the testing will be the same for iOS and Android applications. Please look at "Testing Session Management" in Android for a detailed explanation of this test case.


### Testing the Logout Functionality

It is important to clarify that this control is at the server side, so the testing will be the same for iOS and Android applications. Please look at "Testing the Logout Functionality" in Android for a detailed explanation of this test case.

### Testing the Password Policy

It is important to clarify that this control is at the server side, so the testing will be the same for iOS and Android applications. Please look at "Testing the Password Policy" in Android for a detailed explanation of this test case.


### Testing Excessive Login Attempts

It is important to clarify that this control is at the server side, so the testing will be the same for iOS and Android applications. Please look at "Testing Excessive Login Attempts" in Android for a detailed explanation of this test case.


### Testing Biometric Authentication

#### Overview

-- TODO [Provide a general description of the issue "Testing Biometric Authentication".]

#### Static Analysis

-- TODO [Describe how to assess this given either the source code or installer package (APK/IPA/etc.), but without running the app. Tailor this to the general situation (e.g., in some situations, having the decompiled classes is just as good as having the original source, in others it might make a bigger difference). If required, include a subsection about how to test with or without the original sources.] --

-- TODO [Confirm purpose of remark "Use the &lt;sup&gt; tag to reference external sources, e.g. Meyer's recipe for tomato soup<sup>[1]</sup>."] --

##### With Source Code

-- TODO [Add content for "Testing Biometric Authentication" with source code] --

##### Without Source Code

-- TODO [Add content for "Testing Biometric Authentication" without source code] --

#### Dynamic Analysis

-- TODO [Describe how to test for this issue "Testing Biometric Authentication" by running and interacting with the app. This can include everything from simply monitoring network traffic or aspects of the app’s behavior to code injection, debugging, instrumentation, etc.] --

#### Remediation

-- TODO [Describe the best practices that developers should follow to prevent this issue "Testing Biometric Authentication".] --

#### References

##### OWASP Mobile Top 10 2016
* M4 - Insecure Authentication - https://www.owasp.org/index.php/Mobile_Top_10_2016-M4-Insecure_Authentication

##### OWASP MASVS
##### OWASP MASVS
* 4.6: "Biometric authentication, if any, is not event-bound (i.e. using an API that simply returns "true" or "false"). Instead, it is based on unlocking the keychain/keystore."

##### CWE

-- TODO [Add relevant CWE for "Testing Biometric Authentication"] --
- CWE-312 - Cleartext Storage of Sensitive Information

##### Info

- [1] Meyer's Recipe for Tomato Soup - http://www.finecooking.com/recipes/meyers-classic-tomato-soup.aspx
- [2] Another Informational Article - http://www.securityfans.com/informational_article.html

##### Tools

-- TODO [Add relevant tools for "Testing Biometric Authentication"] --
* Enjarify - https://github.com/google/enjarify



### Testing the Session Timeout

It is important to clarify that this control is at the server side, so the testing will be the same for iOS and Android applications. Please look at "Testing the Session Timeout" in Android for a detailed explanation of this test case.


### Testing 2-Factor Authentication

It is important to clarify that this control is at the server side, so the testing will be the same for iOS and Android applications. Please look at "Testing 2-factor Authentation" in Android for a detailed explanation of this test case.


### Testing Step-up Authentication

It is important to clarify that this control is at the server side, so the testing will be the same for iOS and Android applications. Please look at "Testing Step-up Authentication" in Android for a detailed explanation of this test case.


### Testing User Device Management

#### Overview

-- TODO [Provide a general description of the issue "Testing User Device Management".] --

#### Static Analysis

-- TODO [Describe how to assess this given either the source code or installer package (APK/IPA/etc.), but without running the app. Tailor this to the general situation (e.g., in some situations, having the decompiled classes is just as good as having the original source, in others it might make a bigger difference). If required, include a subsection about how to test with or without the original sources.] --

-- TODO [Confirm purpose of remark "Use the &lt;sup&gt; tag to reference external sources, e.g. Meyer's recipe for tomato soup<sup>[1]</sup>." ] --

-- TODO [Add content for "Testing User Device Management" with source code] --


#### Dynamic Analysis

-- TODO [Describe how to test for this issue "Testing User Device Management" by running and interacting with the app. This can include everything from simply monitoring network traffic or aspects of the app’s behavior to code injection, debugging, instrumentation, etc.] --

#### Remediation

-- TODO [Describe the best practices that developers should follow to prevent this issue "Testing User Device Management".] --

#### References

##### OWASP Mobile Top 10 2016
* M4 - Insecure Authentication - https://www.owasp.org/index.php/Mobile_Top_10_2016-M4-Insecure_Authentication

##### OWASP MASVS
* 4.10: "The app informs the user of all login activities with his or her account. Users are able view a list of devices used to access the account, and to block specific devices."

##### CWE

-- TODO [Add relevant CWE for "Testing User Device Management"] --
- CWE-312 - Cleartext Storage of Sensitive Information

##### Info

- [1] Meyer's Recipe for Tomato Soup - http://www.finecooking.com/recipes/meyers-classic-tomato-soup.aspx
- [2] Another Informational Article - http://www.securityfans.com/informational_article.html

##### Tools

-- TODO [Add relevant tools for "Testing User Device Management"] --
* Enjarify - https://github.com/google/enjarify
