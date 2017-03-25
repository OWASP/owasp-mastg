## Testing Authentication

### Verifying that Users Are Authenticated Properly

#### Overview

-- TODO [Provide a general description of the issue "Verifying that Users Are Authenticated Properly".] --

-- TODO [One recommended best practice is that authentication must be enforced on the server. List other recommendations here.] --

Some applications are doing the authentication relying on the client side, that means that the developer creates some method that will check the username and password on the client side instead of sending the credentials into the backend API. So in that situation, it is possible with the help of some tools to bypass login forms and get access to the application.

#### Static Analysis

##### With Source Code

-- TODO [Add content on "Verifying that Users Are Authenticated Properly" with source code] --

##### Without Source Code

-- TODO [Add content on "Verifying that Users Are Authenticated Properly" without source code] --

#### Dynamic Analysis

-- TODO [Describe how to test for this issue "Verifying that Users Are Authenticated Properly" by running and interacting with the app. This can include everything from simply monitoring network traffic or aspects of the app’s behavior to code injection, debugging, instrumentation, etc.] --

#### Remediation

-- TODO [Describe the best practices that developers should follow to prevent this issue "Verifying that Users Are Authenticated Properly".] --

#### References

##### OWASP Mobile Top 10 2014

* M3 - Insufficient Transport Layer Protection - https://www.owasp.org/index.php/Mobile_Top_10_2014-M3

##### OWASP MASVS

-- TODO [Update reference below "VX.Y" for "Verifying that Users Are Authenticated Properly"] --
- VX.Y: "Requirement text, e.g. 'the keyboard cache is disabled on text inputs that process sensitive data'."

##### CWE

-- TODO [Add relevant CWE for "Verifying that Users Are Authenticated Properly"] --
- CWE-312 - Cleartext Storage of Sensitive Information

##### Info

- [1] Meyer's Recipe for Tomato Soup - http://www.finecooking.com/recipes/meyers-classic-tomato-soup.aspx
- [2] Another Informational Article - http://www.securityfans.com/informational_article.html

##### Tools

-- TODO [Add relevant tools for "Verifying that Users Are Authenticated Properly"] --
* Enjarify - https://github.com/google/enjarify

### Testing Session Management

#### Overview

-- TODO [Provide a general description of the issue "Testing Session Management".] --

##### Recommended best Practices

-- TODO [Develop content for Recommended best Practices for "Testing Session Management".] --
- A "logout" function should exist that allows the user to terminate the session.

#### Static Analysis

-- TODO [Describe how to assess this given either the source code or installer package (APK/IPA/etc.), but without running the app. Tailor this to the general situation (e.g., in some situations, having the decompiled classes is just as good as having the original source, in others it might make a bigger difference). If required, include a subsection about how to test with or without the original sources.] --

-- TODO [Confirm purpose of remark "Use the &lt;sup&gt; tag to reference external sources, e.g. Meyer's recipe for tomato soup<sup>[1]</sup>." ] --

##### With Source Code

-- TODO [Add content on "Testing Session Management" with source code] --

##### Without Source Code

-- TODO [Add content on "Testing Session Management" without source code] --

#### Dynamic Analysis

-- TODO [Describe how to test for this issue "Testing Session Management" by running and interacting with the app. This can include everything from simply monitoring network traffic or aspects of the app’s behavior to code injection, debugging, instrumentation, etc.] --

#### Remediation

-- TODO [Describe the best practices that developers should follow to prevent this issue "Testing Session Management".] --

#### References

##### OWASP Mobile Top 10 2014

* M3 - Insufficient Transport Layer Protection - https://www.owasp.org/index.php/Mobile_Top_10_2014-M3

##### OWASP MASVS

-- TODO [Update reference below "VX.Y" for "Testing Session Management"] --
- VX.Y: "Requirement text, e.g. 'the keyboard cache is disabled on text inputs that process sensitive data'."

##### CWE

-- TODO [Add relevant CWE for "Testing Session Management"] --
- CWE-312 - Cleartext Storage of Sensitive Information

##### Info

- [1] Meyer's Recipe for Tomato Soup - http://www.finecooking.com/recipes/meyers-classic-tomato-soup.aspx
- [2] Another Informational Article - http://www.securityfans.com/informational_article.html

##### Tools

-- TODO [Add relevant tools for "Testing Session Management"] --
* Enjarify - https://github.com/google/enjarify

### Testing the Logout Functionality

#### Overview

Session termination is an important part of the session lifecycle. Reducing the lifetime of the session tokens to a minimum decreases the likelihood of a successful session hijacking attack.
 
The scope for this test case is to validate that the application has a logout functionality and it effectively terminates the session on client and server side.
 
#### Testing

To verify the correct implementation of a logout functionality, dynamic analysis should be applied by using an interception proxy. This technique can be applied to both, Android and iOS platform.  
Static Analysis

If server side code is available, it should be reviewed to validate that the session is being terminated as part of the logout functionality.

The check needed here will be different depending on the technology used. Here are different examples on how a session can be terminated in order to implement a proper logout on server side:
- Spring (Java) - http://docs.spring.io/spring-security/site/docs/current/apidocs/org/springframework/security/web/authentication/logout/SecurityContextLogoutHandler.html
-   Ruby on Rails -  http://guides.rubyonrails.org/security.html
- PHP - http://php.net/manual/en/function.session-destroy.php
-   JSF - http://jsfcentral.com/listings/A20158?link
-   ASP.Net - https://msdn.microsoft.com/en-us/library/ms524798(v=vs.90).aspx
-   Amazon AWS - http://docs.aws.amazon.com/appstream/latest/developerguide/rest-api-session-terminate.html

#### Dynamic Analysis

For a dynamic analysis of the application an interception proxy should be used. Please see section XXX on how to set it up.
The following steps can be applied to check if the logout is implemented properly.  
1.  Log into the application.
2.  Do a couple of operations that require authentication inside the application.
3.  Perform a logout operation.
4.  Resend one of the operations detailed in step 2 using an interception proxy. For example, with Burp Repeater. The purpose of this is to send to the server a request with the token that has been invalidated in step 3.
 
If the session is correctly terminated on the server side, either an error message or redirect to the login page will be sent back to the client. On the other hand, if you have the same response you had in step 2, then, this session is still valid and has not been correctly terminated on the server side.

A detailed explanation with more test cases, can also be found in the OWASP Web Testing Guide (OTG-SESS-006) [1].

#### Remediation 

One of the most common errors done by developers to a logout functionality is simply not destroying the session object in the server side. This leads to a state where the session is still alive even though the user logs out of the application. The session remains alive, and if an attacker get’s in possession of a valid session he can still use it and a user cannot even protect himself by logging out or if there are no session timeout controls in place.
 
To mitigate it, the logout function on the server side must invalidate this session identifier immediately after logging out to prevent it to be reused by an attacker that could have intercepted it.
 
Related to this, it must be checked that after calling an operation with an expired token, the application does not generate another valid token. This could lead to another authentication bypass.
 
Many Apps do not automatically logout a user, because of customer convenience. The user logs in once, afterwards a token is generated on server side and stored within the applications internal storage and used for authentication when the application starts instead of asking again for user credentials. There should still be a logout function available within the application and this should work according to best practices by also destroying the session on server side.

#### References

##### OWASP Mobile Top 10 2014

* M3 - Insufficient Transport Layer Protection - https://www.owasp.org/index.php/Mobile_Top_10_2014-M3

##### OWASP MASVS

-- TODO [Update reference below "VX.Y" for "Testing the Logout Functionality"] --
- VX.Y: "Requirement text, e.g. 'the keyboard cache is disabled on text inputs that process sensitive data'."

##### CWE

-- TODO [Add relevant CWE for "Testing the Logout Functionality"] --
- CWE-312 - Cleartext Storage of Sensitive Information

##### Info

- [1] https://www.owasp.org/index.php/Testing_for_logout_functionality_(OTG-SESS-006)
- [2] https://www.owasp.org/index.php/Session_Management_Cheat_Sheet

##### Tools

-- TODO [Add relevant tools for "Testing the Logout Functionality"] --
* Enjarify - https://github.com/google/enjarify

### Testing the Password Policy

#### Overview

-- TODO [Provide a general description of the issue "Testing the Password Policy".] --

#### Static Analysis

-- TODO [Describe how to assess this given either the source code or installer package (APK/IPA/etc.), but without running the app. Tailor this to the general situation (e.g., in some situations, having the decompiled classes is just as good as having the original source, in others it might make a bigger difference). If required, include a subsection about how to test with or without the original sources.] --

-- TODO [Confirm purpose of "Use the &lt;sup&gt; tag to reference external sources, e.g. Meyer's recipe for tomato soup<sup>[1]</sup>."] --

##### With Source Code

-- TODO [Add content on "Testing the Password Policy" with source code] --

##### Without Source Code

-- TODO [Add content on "Testing the Password Policy" without source code] --

#### Dynamic Analysis

-- TODO [Describe how to test for this issue "Testing the Password Policy" by running and interacting with the app. This can include everything from simply monitoring network traffic or aspects of the app’s behavior to code injection, debugging, instrumentation, etc.] --

#### Remediation

-- TODO [Describe the best practices that developers should follow to prevent this issue "Testing the Password Policy".] --

#### References

##### OWASP Mobile Top 10 2014

* M3 - Insufficient Transport Layer Protection - https://www.owasp.org/index.php/Mobile_Top_10_2014-M3

##### OWASP MASVS

-- TODO [Update reference below "VX.Y" for "Testing the Password Policy"] --
- VX.Y: "Requirement text, e.g. 'the keyboard cache is disabled on text inputs that process sensitive data'."

##### CWE

-- TODO [Add relevant CWE for "Testing the Password Policy"] --
- CWE-312 - Cleartext Storage of Sensitive Information

##### Info

- [1] Meyer's Recipe for Tomato Soup - http://www.finecooking.com/recipes/meyers-classic-tomato-soup.aspx
- [2] Another Informational Article - http://www.securityfans.com/informational_article.html

##### Tools

-- TODO [Add relevant tools for "Testing the Password Policy"] --
* Enjarify - https://github.com/google/enjarify

### Testing Excessive Login Attempts

#### Overview

We all have heard about brute force attacks, right? That is one of the simplest attack types, as already many tools are available that work out of the box. It also doesn’t require a deep technical understanding of the target, as only a list of username and password combinations is sufficient to execute the attack. Once a valid combination of credentials is identified access to the application is possible and the account can be compromised.
 
To be protected against these kind of attacks, applications need to implement a control to block the access after a defined number of incorrect login attempts.
 
Depending on the application that you want to protect, the number of incorrect attempts allowed may vary. For example, in a banking application it should be around three to five attempts, but, in a public forum, it could be a higher number. Once this threshold is reached It also needs to be decided if the account gets locked permanently or temporarily. Locking the account temporarily is also called login throttling.
 
#### Testing

It is important to clarify that this control is at the server side, so the testing will be the same for iOS and Android applications.
Moreover, the test consists by entering the password incorrectly for the defined number of attempts to trigger the account lockout. At that point, the anti-brute force control should be activated and your logon should be rejected when the correct credentials are entered.
  
#### Static Analysis

If server side code is available, it should be reviewed to validate that the session is being terminated as part of the lockout functionality.
Here, we need to check that there is a validation in the logon method that checks if the number of attempts in a credential equals to the maximum number of attempts set. In that case, no logon should be granted
It worths reviewing too that, after a correct attempt, there is a mechanism in place to set the error counter to zero.
 
#### Dynamic Analysis

For a dynamic analysis of the application an interception proxy should be used. Please see section XXX on how to set it up.
The following steps can be applied to check if the lockout mechanism is implemented properly.  
1.  Log in incorrectly for a number of times to trigger the lockout control (generally 3 to 15 incorrect attempts)
2.  Once you have locked out the account, enter the correct logon details to verify if login is not possible anymore.
If this is correctly implemented, when the right password is entered, logon should be denied, as the credential has already been blocked.

#### Remediation

Lockout controls have to be implemented to prevent brute force attacks. See [3] for further mitigation techniques.
It is interesting to clarify that incorrect logon attempts should be cumulative and not linked to a session. If you implement a control to block the credential in your 3rd attempt in the same session, it can be easily bypassed by entering the details wrong two times and get a new session. This will then give another free attempts.

#### References

##### OWASP Mobile Top 10 2014

* M3 - Insufficient Transport Layer Protection - https://www.owasp.org/index.php/Mobile_Top_10_2014-M3

##### OWASP MASVS

-- TODO [Update reference below "VX.Y" for "Testing Excessive Login Attempts"] --
- VX.Y: "Requirement text, e.g. 'the keyboard cache is disabled on text inputs that process sensitive data'."

##### CWE

-- TODO [Add relevant CWE for "Testing Excessive Login Attempts"] --
- CWE-312 - Cleartext Storage of Sensitive Information

##### Info

- [1] https://www.owasp.org/index.php/Testing_for_Weak_lock_out_mechanism_(OTG-AUTHN-003)
- [2] https://www.owasp.org/index.php/Brute_force_attack
- [3] https://www.owasp.org/index.php/Blocking_Brute_Force_Attacks

##### Tools

-- TODO [Add relevant tools for "Testing Excessive Login Attempts"] --
* Enjarify - https://github.com/google/enjarify

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

##### OWASP Mobile Top 10 2014

* M3 - Insufficient Transport Layer Protection - https://www.owasp.org/index.php/Mobile_Top_10_2014-M3

##### OWASP MASVS

-- TODO [Update reference below "VX.Y" for "Testing Biometric Authentication"] --
- VX.Y: "Requirement text, e.g. 'the keyboard cache is disabled on text inputs that process sensitive data'."

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

#### Overview

Compared to web applications most mobile applications don’t have a session timeout mechanism that terminates the session after some period of inactivity and force the user to login again. For most mobile applications users need to enter the credentials once. After authenticating on server side an access token is stored on the device which is used to authenticate. If the token is about to expire the token will be renewed without entering the credentials again. Applications that handle sensitive data like patient data or critical functions like financial transactions should implement a session timeout as a security-in-depth measure that forces users to re-login after a defined period.
 
We will explain here how to check that this control is implemented correctly, both in the client and server side.

#### Testing

To test this, dynamic analysis is an efficient option, as it is easy to validate if this feature is working or not at runtime using an interception proxy. This is similar to test case OMTG-AUTH-002 (Testing the Logout Functionality), but we need to leave the application in idle for the period of time required to trigger the timeout function. Once this condition has been launched, we need to validate that the session is effectively terminated on client and server side.
This technique can be applied to both, Android and iOS platform.

#### Static Analysis

If server side code is available, it should be reviewed that the session timeout functionality is correctly configured and a timeout is triggered after a defined period of time.  
The check needed here will be different depending on the technology used. Here are different examples on how a session timeout can be configured:
- Spring (Java) - http://docs.spring.io/spring-session/docs/current/reference/html5/
-   Ruby on Rails -  https://github.com/rails/rails/blob/318a20c140de57a7d5f820753c82258a3696c465/railties/lib/rails/application/configuration.rb#L130
- PHP - http://php.net/manual/en/session.configuration.php#ini.session.gc-maxlifetime
- ASP.Net - https://msdn.microsoft.com/en-GB/library/system.web.sessionstate.httpsessionstate.timeout(v=vs.110).aspx
-   Amazon AWS - http://docs.aws.amazon.com/ElasticLoadBalancing/latest/DeveloperGuide/config-idle-timeout.html
 
Some applications also have an autologoff functionality in the client side. This is not a mandatory feature, but helps to improve to enforce a session timeout.  To implement this, the client side needs to control the timestamp when the screen has been displayed, and check continuously if the time elapsed is lower than the defined timeout. Once that time matches or excesses the timeout, the logoff method will be invoked, sending a signal to the server side to terminate the session and redirecting the customer to an informative screen.

-- TODO [Change code below from Android code to iOS code + format it as code "Testing the Session Timeout"] --
For Android the following code might be used to implement it [3]:

public class TestActivity extends TimeoutActivity {<br>
 @Override protected void onTimeout() {<br>
  // logout<br>
}<br>
 @Override protected long getTimeoutInSeconds() {<br>
  return 15 * 60; // 15 minutes<br>
}<br>

#### Dynamic Analysis

For a dynamic analysis of the application an interception proxy should be used. Please see section XXX on how to set it up.
The following steps can be applied to check if the session timeout is implemented properly.  
-   Log into the application.
-   Do a couple of operations that require authentication inside the application.
-   Leave the application in idle until the session expires (for testing purposes, a reasonable timeout can be configured, and amended later in the final version)
 
Resend one of the operations executed in step 2 using an interception proxy. For example, with Burp Repeater. The purpose of this is to send to the server a request with the session ID that has been invalidated when the session has expired.
If session timeout has been correctly configured on the server side, either an error message or redirect to the login page will be sent back to the client. On the other hand, if you have the same response you had in step 2, then, this session is still valid, which means that the session timeout control is not configured correctly.
More information can also be found in the OWASP Web Testing Guide (OTG-SESS-007) [1].

#### Remediation

Most of the frameworks have a parameter to configure the session timeout. This parameter should be set accordingly to the best practices specified of the documentation of the framework. The best practice timeout setting may vary between 5 to 30 minutes, depending on the sensitivity of your application and the use case of it.
Regarding autologoff, the pseudocode of the implementation should be as follow:

Function autologoff<br>
    Get timestamp_start<br>
    While application_is_running<br>
        time=timestamp-timestamp_start<br>
        If time=logoff_condition<br>
            Call logoff<br>
        EndIf<br>
    EndWhile<br>
End<br>

#### References

##### OWASP Mobile Top 10 2014

* M3 - Insufficient Transport Layer Protection - https://www.owasp.org/index.php/Mobile_Top_10_2014-M3

##### OWASP MASVS

-- TODO [Update reference below "VX.Y" for "Testing the Session Timeout"] --
- VX.Y: "Requirement text, e.g. 'the keyboard cache is disabled on text inputs that process sensitive data'."

##### CWE

-- TODO [Add relevant CWE for "Testing the Session Timeout"] --
- CWE-312 - Cleartext Storage of Sensitive Information

##### Info

- [1] OWASP web application test guide https://www.owasp.org/index.php/Test_Session_Timeout_(OTG-SESS-007)
- [2] OWASP Session management cheatsheet https://www.owasp.org/index.php/Session_Management_Cheat_Sheet

##### Tools

-- TODO [Add relevant tools for "Testing the Session Timeout"] --
* Enjarify - https://github.com/google/enjarify


### Testing 2-Factor Authentication

#### Overview

-- TODO [Provide a general description of the issue "Testing 2-Factor Authentication".] --

#### Static Analysis

-- TODO [Describe how to assess this given either the source code or installer package (APK/IPA/etc.), but without running the app. Tailor this to the general situation (e.g., in some situations, having the decompiled classes is just as good as having the original source, in others it might make a bigger difference). If required, include a subsection about how to test with or without the original sources.] --

-- TODO [Confirm purpose of remark "Use the &lt;sup&gt; tag to reference external sources, e.g. Meyer's recipe for tomato soup<sup>[1]</sup>." ] --

##### With Source Code

-- TODO [Add content on "Testing 2-Factor Authentication" with source code] --

##### Without Source Code

-- TODO [Add content on "Testing 2-Factor Authentication" without source code] --

#### Dynamic Analysis

-- TODO [Describe how to test for this issue "Testing 2-Factor Authentication" by running and interacting with the app. This can include everything from simply monitoring network traffic or aspects of the app’s behavior to code injection, debugging, instrumentation, etc.] --

#### Remediation

-- TODO [Describe the best practices that developers should follow to prevent this issue "Testing 2-Factor Authentication".] --

#### References

##### OWASP Mobile Top 10 2014

* M3 - Insufficient Transport Layer Protection - https://www.owasp.org/index.php/Mobile_Top_10_2014-M3

##### OWASP MASVS

-- TODO [Update reference below "VX.Y" in "Testing 2-Factor Authentication"] --
- VX.Y: "Requirement text, e.g. 'the keyboard cache is disabled on text inputs that process sensitive data'."

##### CWE

-- TODO [Add relevant CWE for "Testing 2-Factor Authentication"] --
- CWE-312 - Cleartext Storage of Sensitive Information

##### Info

- [1] Meyer's Recipe for Tomato Soup - http://www.finecooking.com/recipes/meyers-classic-tomato-soup.aspx
- [2] Another Informational Article - http://www.securityfans.com/informational_article.html

##### Tools

-- TODO [Add relevant tools for "Testing 2-Factor Authentication"] --
* Enjarify - https://github.com/google/enjarify

### Testing Step-up Authentication

#### Overview

-- TODO [Provide a general description of the issue "Testing Step-up Authentication".] --

#### Static Analysis

-- TODO [Describe how to assess this given either the source code or installer package (APK/IPA/etc.), but without running the app. Tailor this to the general situation (e.g., in some situations, having the decompiled classes is just as good as having the original source, in others it might make a bigger difference). If required, include a subsection about how to test with or without the original sources.] --

-- TODO [Confirm purpose of remark "Use the &lt;sup&gt; tag to reference external sources, e.g. Meyer's recipe for tomato soup<sup>[1]</sup>."] --

##### With Source Code

-- TODO [Add content on "Testing Step-up Authentication" with source code] --

##### Without Source Code

-- TODO [Add content on "Testing Step-up Authentication" without source code] --

#### Dynamic Analysis

-- TODO [Describe how to test for this issue "Testing Step-up Authentication" by running and interacting with the app. This can include everything from simply monitoring network traffic or aspects of the app’s behavior to code injection, debugging, instrumentation, etc.] --

#### Remediation

-- TODO [Describe the best practices that developers should follow to prevent this issue "Testing Step-up Authentication".] --

#### References

##### OWASP Mobile Top 10 2014

* M3 - Insufficient Transport Layer Protection - https://www.owasp.org/index.php/Mobile_Top_10_2014-M3

##### OWASP MASVS

-- TODO [Update reference below "VX.Y" for "Testing Step-up Authentication"] --
- VX.Y: "Requirement text, e.g. 'the keyboard cache is disabled on text inputs that process sensitive data'."

##### CWE

-- TODO [Add relevant CWE for "Testing Step-up Authentication"] --
- CWE-312 - Cleartext Storage of Sensitive Information

##### Info

- [1] Meyer's Recipe for Tomato Soup - http://www.finecooking.com/recipes/meyers-classic-tomato-soup.aspx
- [2] Another Informational Article - http://www.securityfans.com/informational_article.html

##### Tools

-- TODO [Add relevant tools for "Testing Step-up Authentication"] --
* Enjarify - https://github.com/google/enjarify

### Testing User Device Management

#### Overview

-- TODO [Provide a general description of the issue "Testing User Device Management".] --

#### Static Analysis

-- TODO [Describe how to assess this given either the source code or installer package (APK/IPA/etc.), but without running the app. Tailor this to the general situation (e.g., in some situations, having the decompiled classes is just as good as having the original source, in others it might make a bigger difference). If required, include a subsection about how to test with or without the original sources.] --

-- TODO [Confirm purpose of remark "Use the &lt;sup&gt; tag to reference external sources, e.g. Meyer's recipe for tomato soup<sup>[1]</sup>." ] --

##### With Source Code

-- TODO [Add content for "Testing User Device Management" with source code] --

##### Without Source Code

-- TODO [Add content for "Testing User Device Management" without source code] --

#### Dynamic Analysis

-- TODO [Describe how to test for this issue "Testing User Device Management" by running and interacting with the app. This can include everything from simply monitoring network traffic or aspects of the app’s behavior to code injection, debugging, instrumentation, etc.] --

#### Remediation

-- TODO [Describe the best practices that developers should follow to prevent this issue "Testing User Device Management".] --

#### References

##### OWASP Mobile Top 10 2014

* M3 - Insufficient Transport Layer Protection - https://www.owasp.org/index.php/Mobile_Top_10_2014-M3

##### OWASP MASVS

-- TODO [Update reference below "VX.Y" for "Testing User Device Management"] --
- VX.Y: "Requirement text, e.g. 'the keyboard cache is disabled on text inputs that process sensitive data'."

##### CWE

-- TODO [Add relevant CWE for "Testing User Device Management"] --
- CWE-312 - Cleartext Storage of Sensitive Information

##### Info

- [1] Meyer's Recipe for Tomato Soup - http://www.finecooking.com/recipes/meyers-classic-tomato-soup.aspx
- [2] Another Informational Article - http://www.securityfans.com/informational_article.html

##### Tools

-- TODO [Add relevant tools for "Testing User Device Management"] --
* Enjarify - https://github.com/google/enjarify


