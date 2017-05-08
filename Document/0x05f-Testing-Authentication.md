## Testing Authentication

### Verify that Users Are Properly Authenticated

#### Overview

-- TODO [Provide a general description of the issue.] --

#### Static Analysis

-- TODO [Describe how to assess this given either the source code or installer package (APK/IPA/etc.), but without running the app. Tailor this to the general situation (e.g., in some situations, having the decompiled classes is just as good as having the original source, in others it might make a bigger difference). If required, include a subsection about how to test with or without the original sources.] --

-- TODO [Confirm remark "Use the &lt;sup&gt; tag to reference external sources, e.g. Meyer's recipe for tomato soup<sup>[1]</sup>."] --

-- TODO [Develop content on Verifying that Users Are Properly Authenticated with source code] --


#### Dynamic Analysis

-- TODO [Describe how to test for this issue "Verifying that Users Are Properly Authenticated" by running and interacting with the app. This can include everything from simply monitoring network traffic or aspects of the app’s behavior to code injection, debugging, instrumentation, etc.] --

#### Remediation

-- TODO [Describe the best practices that developers should follow to prevent this issue.] --

#### References

##### OWASP Mobile Top 10 2016
* M4 - Insecure Authentication - https://www.owasp.org/index.php/Mobile_Top_10_2016-M4-Insecure_Authentication

##### OWASP MASVS
- 4.1: "If the app provides users with access to a remote service, an acceptable form of authentication such as username/password authentication is performed at the remote endpoint."

##### CWE

-- TODO [Add relevant CWE for "Verifying that Users Are Properly Authenticated"] --
- CWE-312 - Cleartext Storage of Sensitive Information

##### Info

- [1] Meyer's Recipe for Tomato Soup - http://www.finecooking.com/recipes/meyers-classic-tomato-soup.aspx
- [2] Another Informational Article - http://www.securityfans.com/informational_article.html

##### Tools

-- TODO [Add relevant tools for "Verifying that Users Are Properly Authenticated"] --
* Enjarify - https://github.com/google/enjarify


### Testing Session Management

#### Overview

-- TODO [Provide a general description of the issue "Testing Session Management".] --

#### Static Analysis

-- TODO [Describe how to assess this given either the source code or installer package (APK/IPA/etc.), but without running the app. Tailor this to the general situation (e.g., in some situations, having the decompiled classes is just as good as having the original source, in others it might make a bigger difference). If required, include a subsection about how to test with or without the original sources.] --

-- TODO [Confirm remark "Use the &lt;sup&gt; tag to reference external sources, e.g. Meyer's recipe for tomato soup<sup>[1]</sup>."] --

-- TODO [Develop content on "Testing Session Management" with source code] --

#### Dynamic Analysis

-- TODO [Describe how to test for this issue "Testing Session Management" by running and interacting with the app. This can include everything from simply monitoring network traffic or aspects of the app’s behavior to code injection, debugging, instrumentation, etc.] --

#### Remediation

-- TODO [Describe the best practices that developers should follow to prevent this issue "Testing Session Management".] --

#### References

##### OWASP Mobile Top 10 2016
* M4 - Insecure Authentication - https://www.owasp.org/index.php/Mobile_Top_10_2016-M4-Insecure_Authentication

##### OWASP MASVS
* 4.2: "The remote endpoint uses randomly generated access tokens to authenticate client requests without sending the user's credentials."

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

##### Static Analysis 

If server side code is available, it should be reviewed to validate that the session is being terminated as part of the logout functionality.
The check needed here will be different depending on the technology used. Here are different examples on how a session can be terminated in order to implement a proper logout on server side:
- Spring (Java) - http://docs.spring.io/spring-security/site/docs/current/apidocs/org/springframework/security/web/authentication/logout/SecurityContextLogoutHandler.html
- Ruby on Rails -  http://guides.rubyonrails.org/security.html
- PHP - http://php.net/manual/en/function.session-destroy.php
- JSF - http://jsfcentral.com/listings/A20158?link
- ASP.Net - https://msdn.microsoft.com/en-us/library/ms524798(v=vs.90).aspx
- Amazon AWS - http://docs.aws.amazon.com/appstream/latest/developerguide/rest-api-session-terminate.html

#### Dynamic Analysis

For a dynamic analysis of the application an interception proxy should be used. The following steps can be applied to check if the logout is implemented properly.  
1.  Log into the application.
2.  Do a couple of operations that require authentication inside the application.
3.  Perform a logout operation.
4.  Resend one of the operations detailed in step 2 using an interception proxy. For example, with Burp Repeater. The purpose of this is to send to the server a request with the token that has been invalidated in step 3.
 
If the session is correctly terminated on the server side, either an error message or redirect to the login page will be sent back to the client. On the other hand, if you have the same response you had in step 2, then, this session is still valid and has not been correctly terminated on the server side.
A detailed explanation with more test cases, can also be found in the OWASP Web Testing Guide (OTG-SESS-006)<sup>[1]</sup>.

#### Remediation 

One of the most common errors done when implementing a logout functionality is simply not destroying the session object on server side. This leads to a state where the session is still alive even though the user logs out of the application. The session remains alive, and if an attacker get’s in possession of a valid session he can still use it and a user cannot even protect himself by logging out or if there are no session timeout controls in place.
 
To mitigate it, the logout function on the server side must invalidate this session identifier immediately after logging out to prevent it to be reused by an attacker that could have intercepted it.
 
Related to this, it must be checked that after calling an operation with an expired token, the application does not generate another valid token. This could lead to another authentication bypass.
 
Many Apps do not automatically logout a user, because of customer convenience. The user logs in once, afterwards a token is generated on server side and stored within the applications internal storage and used for authentication when the application starts instead of asking again for user credentials. If the token expires a refresh token might be used (OAuth2) to transparently reinitiate the session for the user. There should still be a logout function available within the application and this should work according to best practices by also destroying the session on server side.

#### References

##### OWASP Mobile Top 10 2016
* M4 - Insecure Authentication - https://www.owasp.org/index.php/Mobile_Top_10_2016-M4-Insecure_Authentication

##### OWASP MASVS
-- TODO [Update reference "VX.Y" below for "Testing the Logout Functionality"] --
- 4.3: "The remote endpoint terminates the existing session when the user logs out."

##### CWE

-- TODO [Add relevant CWE for "Testing the Logout Functionality"] --
- CWE-312 - Cleartext Storage of Sensitive Information

##### Info

* [1] OTG-SESS-006 - https://www.owasp.org/index.php/Testing_for_logout_functionality
* [2] Session Management Cheat Sheet - https://www.owasp.org/index.php/Session_Management_Cheat_Sheet


### Testing the Password Policy

#### Overview

-- TODO [Provide a general description of the issue "Testing the Password Policy".] --

#### Static Analysis

When testing a password policy, a well-defined rule set can be used to verify that source code not contain any previously identified technical or logical security flew. A exemplary rule set (source: VT Password<sup>[1]</sup>) is given below:
* AllowedCharacterRule - Does a password contain only a specific list of characters
* AlphabeticalSequenceRule - Does a password contain an alphabetical sequence
* CharacterCharacteristicRule - Does a password contain the desired mix of character types
* DictionaryRule - Does a password match a word in a dictionary
* DictionarySubstringRule - Does a password contain a word in a dictionary
* DigitCharacterRule - Does a password contain a digit
* HistoryRule - Does a password match a previous password, supports hashes
* IllegalCharacterRule - Does a password contain an illegal character
* LengthRule - Is a password of a certain length
* LowercaseCharacterRule - Does a password contain a lowercase character
* NonAlphanumericCharacterRule - Does a password contain a non-alphanumeric character
* NumericalSequenceRule - Does a password contain a numerical sequence
* RegexRule - Does a password match a regular expression
* RepeatCharacterRegexRule - Does a password contain a repeated character
* SequenceRule - Does a password contain a keyboard sequence
* SourceRule - Does a password match the password from another system or source
* QwertySequenceRule - Does a password contain a QWERTY keyboard sequence
* UppercaseCharacterRule - Does a password contain an uppercase character
* UsernameRule - Does a password contain a username
* WhitespaceRule - Does a password contain whitespace

-- TODO [Describe how to assess this given either the source code or installer package (APK/IPA/etc.), but without running the app. Tailor this to the general situation (e.g., in some situations, having the decompiled classes is just as good as having the original source, in others it might make a bigger difference). If required, include a subsection about how to test with or without the original sources.] --

-- TODO [Confirm remark "Use the &lt;sup&gt; tag to reference external sources, e.g. Meyer's recipe for tomato soup<sup>[1]</sup>." ] --

-- TODO [Develop content on Testing the Password Policy with source code] --

#### Dynamic Analysis

-- TODO [Describe how to test for this issue "Testing the Password Policy" by running and interacting with the app. This can include everything from simply monitoring network traffic or aspects of the app’s behavior to code injection, debugging, instrumentation, etc.] --

#### Remediation

Issues related to Password Policy can easily be mitigated if application architecture is built with it from the beginning of the develpoment. Using regular expressions, developers could implement these policy settings. A list of regaular expressions which was discused in stackoverflow<sup>[2]</sup> is given below:
* ^                 # start-of-string
* (?=.*[0-9])       # a digit must occur at least once
* (?=.*[a-z])       # a lower case letter must occur at least once
* (?=.*[A-Z])       # an upper case letter must occur at least once
* (?=.*[@#$%^&+=])  # a special character must occur at least once
* (?=\S+$)          # no whitespace allowed in the entire string
* .{8,}             # anything, at least eight places though
* $                 # end-of-string

-- TODO [Describe the best practices that developers should follow to prevent this issue "Testing the Password Policy".] --

#### References

##### OWASP Mobile Top 10 2016
* M4 - Insecure Authentication - https://www.owasp.org/index.php/Mobile_Top_10_2016-M4-Insecure_Authentication

##### OWASP MASVS
* 4.4: "A password policy exists and is enforced at the remote endpoint."

##### OWASP Testing Guide v4
* 4.5 - Authentication Testing - https://www.owasp.org/index.php/Testing_for_authentication

##### CWE

-- TODO [Add relevant CWE for "Testing the Password Policy"] --
- CWE-312 - Cleartext Storage of Sensitive Information

##### Info

- [1] VT Password - https://code.google.com/archive/p/vt-middleware/wikis/vtpassword.wiki
- [2] Stackoverflow - http://stackoverflow.com/questions/3802192/regexp-java-for-password-validation

##### Tools

-- TODO [Add relevant tools for "Testing the Password Policy"] --
* Enjarify - https://github.com/google/enjarify




### Testing Excessive Login Attempts

#### Overview

We all have heard about brute force attacks. That is one of the simplest attack types, as already many tools are available that work out of the box. It also doesn’t require a deep technical understanding of the target, as only a list of username and password combinations is sufficient to execute the attack. Once a valid combination of credentials is identified access to the application is possible and the account can be compromised.
 
To be protected against these kind of attacks, applications need to implement a control to block the access after a defined number of incorrect login attempts.
 
Depending on the application that you want to protect, the number of incorrect attempts allowed may vary. For example, in a banking application it should be around three to five attempts, but, in a public forum, it could be a higher number. Once this threshold is reached it also needs to be decided if the account gets locked permanently or temporarily. Locking the account temporarily is also called login throttling.
 
It is important to clarify that this control is at the server side, so the testing will be the same for iOS and Android applications.
Moreover, the test consists by entering the password incorrectly for the defined number of attempts to trigger the account lockout. At that point, the anti-brute force control should be activated and your logon should be rejected when the correct credentials are entered.

#### Static Analysis

It need to be checked that a validation method exists during logon that checks if the number of attempts for a username equals to the maximum number of attempts set. In that case, no logon should be granted once this threshold is meet.
After a correct attempt, there should also be a mechanism in place to set the error counter to zero.


#### Dynamic Analysis

For a dynamic analysis of the application an interception proxy should be used. The following steps can be applied to check if the lockout mechanism is implemented properly.  
1.  Log in incorrectly for a number of times to trigger the lockout control (generally 3 to 15 incorrect attempts)
2.  Once you have locked out the account, enter the correct logon details to verify if login is not possible anymore.
If this is correctly implemented logon should be denied when the right password is entered, as the credential has already been blocked.

#### Remediation

Lockout controls have to be implemented on server side to prevent brute force attacks. Further mitigation techniques are described by the OWASP in Blocking Brute Force Attacks<sup>[3]</sup>.
It is interesting to clarify that incorrect logon attempts should be cumulative and not linked to a session. If you implement a control to block the credential in your 3rd attempt in the same session, it can be easily bypassed by entering the details wrong two times and get a new session. This will then give another two free attempts.

#### References

##### OWASP Mobile Top 10 2016
* M4 - Insecure Authentication - https://www.owasp.org/index.php/Mobile_Top_10_2016-M4-Insecure_Authentication

##### OWASP MASVS
* 4.5: "The remote endpoint implements an exponential back-off, or temporarily locks the user account, when incorrect authentication credentials are submitted an excessive number of times ."

##### CWE

-- TODO [Add relevant CWE for "Testing Excessive Login Attempts"] --
- CWE-312 - Cleartext Storage of Sensitive Information

##### Info
* [1] OTG-AUTHN-003 - https://www.owasp.org/index.php/Testing_for_Weak_lock_out_mechanism
* [2] Brute Force Attacks - https://www.owasp.org/index.php/Brute_force_attack
* [3] Blocking Brute Force Attacks - https://www.owasp.org/index.php/Blocking_Brute_Force_Attacks

##### Tools

* Burp Suite Professional - https://portswigger.net/burp/
* OWASP ZAP - https://www.owasp.org/index.php/OWASP_Zed_Attack_Proxy_Project


### Testing Biometric Authentication

#### Overview

-- TODO [Provide a general description of the issue "Testing Biometric Authentication".] --

#### Static Analysis

-- TODO [Describe how to assess this given either the source code or installer package (APK/IPA/etc.), but without running the app. Tailor this to the general situation (e.g., in some situations, having the decompiled classes is just as good as having the original source, in others it might make a bigger difference). If required, include a subsection about how to test with or without the original sources.] --

-- TODO [Confirm remark "Use the &lt;sup&gt; tag to reference external sources, e.g. Meyer's recipe for tomato soup<sup>[1]</sup>."] --

-- TODO [Develop content on "Testing Biometric Authentication" with source code] --

#### Dynamic Analysis

-- TODO [Describe how to test for this issue "Testing Biometric Authentication" by running and interacting with the app. This can include everything from simply monitoring network traffic or aspects of the app’s behavior to code injection, debugging, instrumentation, etc.] --

#### Remediation

-- TODO [Describe the best practices that developers should follow to prevent this issue "Testing Biometric Authentication".] --

#### References

##### OWASP Mobile Top 10 2016
* M4 - Insecure Authentication - https://www.owasp.org/index.php/Mobile_Top_10_2016-M4-Insecure_Authentication

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

#### Overview

Compared to web applications most mobile applications don’t have a session timeout mechanism that terminates the session after some period of inactivity and force the user to login again. For most mobile applications users need to enter the credentials once. After authenticating on server side an access token is stored on the device which is used to authenticate. If the token is about to expire the token will be renewed without entering the credentials again. Applications that handle sensitive data like patient data or critical functions like financial transactions should implement a session timeout as a security-in-depth measure that forces users to re-login after a defined period.
 
We will explain here how to check that this control is implemented correctly, both in the client and server side.

To test this, dynamic analysis is an efficient option, as it is easy to validate if this feature is working or not at runtime using an interception proxy. This is similar to test case "Testing the Logout Functionality", but we need to leave the application in idle for the period of time required to trigger the timeout function. Once this condition has been launched, we need to validate that the session is effectively terminated on client and server side.

#### Static Analysis

If server side code is available, it should be reviewed that the session timeout functionality is correctly configured and a timeout is triggered after a defined period of time.  
The check needed here will be different depending on the technology used. Here are different examples on how a session timeout can be configured:
- Spring (Java) - http://docs.spring.io/spring-session/docs/current/reference/html5/
- Ruby on Rails -  https://github.com/rails/rails/blob/318a20c140de57a7d5f820753c82258a3696c465/railties/lib/rails/application/configuration.rb#L130
- PHP - http://php.net/manual/en/session.configuration.php#ini.session.gc-maxlifetime
- ASP.Net - https://msdn.microsoft.com/en-GB/library/system.web.sessionstate.httpsessionstate.timeout(v=vs.110).aspx
- Amazon AWS - http://docs.aws.amazon.com/ElasticLoadBalancing/latest/DeveloperGuide/config-idle-timeout.html
 
Some applications also have an autologoff functionality in the client side. This is not a mandatory feature, but helps to improve to enforce a session timeout.  To implement this, the client side needs to control the timestamp when the screen has been displayed, and check continuously if the time elapsed is lower than the defined timeout. Once that time matches or excesses the timeout, the logoff method will be invoked, sending a signal to the server side to terminate the session and redirecting the customer to an informative screen.
For Android the following code might be used to implement it<sup>[3]</sup>:

```
public class TestActivity extends TimeoutActivity {
@Override protected void onTimeout() {
// logout
}
@Override protected long getTimeoutInSeconds() {
return 15 * 60; // 15 minutes
}
```

#### Dynamic Analysis

For a dynamic analysis of the application an interception proxy should be used. The following steps can be applied to check if the session timeout is implemented properly.  
-   Log into the application.
-   Do a couple of operations that require authentication inside the application.
-   Leave the application in idle until the session expires (for testing purposes, a reasonable timeout can be configured, and amended later in the final version)
 
Resend one of the operations executed in step 2 using an interception proxy. For example, with Burp Repeater. The purpose of this is to send to the server a request with the session ID that has been invalidated when the session has expired.
If session timeout has been correctly configured on the server side, either an error message or redirect to the login page will be sent back to the client. On the other hand, if you have the same response you had in step 2, then, this session is still valid, which means that the session timeout is not configured correctly.
More information can also be found in the OWASP Web Testing Guide (OTG-SESS-007)<sup>[1]</sup>.

#### Remediation

Most of the frameworks have a parameter to configure the session timeout. This parameter should be set accordingly to the best practices specified of the documentation of the framework. The best practice timeout setting may vary between 10 minutes to two hours, depending on the sensitivity of your application and the use case of it.
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

##### OWASP Mobile Top 10 2016
* M4 - Insecure Authentication - https://www.owasp.org/index.php/Mobile_Top_10_2016-M4-Insecure_Authentication

##### OWASP MASVS
* 4.7: "Sessions are terminated at the remote endpoint after a predefined period of inactivity."

##### CWE

-- TODO [Add relevant CWE for "Testing the Session Timeout"] --
- CWE-312 - Cleartext Storage of Sensitive Information

##### Info

* [1] OWASP web application test guide https://www.owasp.org/index.php/Test_Session_Timeout_(OTG-SESS-007)
* [2] OWASP Session management cheatsheet https://www.owasp.org/index.php/Session_Management_Cheat_Sheet
* [3] Logout triggered by Client - https://github.com/zoltanersek/android-timeout-activity

##### Tools

-- TODO [Add relevant tools for "Testing the Session Timeout"] --
* Enjarify - https://github.com/google/enjarify



### Testing 2-Factor Authentication

#### Overview

https://authy.com/blog/security-of-sms-for-2fa-what-are-your-options/
-- TODO [Provide a general description of the issue "Testing 2-Factor Authentication".] --

#### Static Analysis

-- TODO [Describe how to assess this given either the source code or installer package (APK/IPA/etc.), but without running the app. Tailor this to the general situation (e.g., in some situations, having the decompiled classes is just as good as having the original source, in others it might make a bigger difference). If required, include a subsection about how to test with or without the original sources.] --

-- TODO [Confirm remark on "Use the &lt;sup&gt; tag to reference external sources, e.g. Meyer's recipe for tomato soup<sup>[1]</sup>."] --

-- TODO [Develop content on Testing 2-Factor Authentication with source code] --


#### Dynamic Analysis

-- TODO [Describe how to test for this issue "Testing 2-Factor Authentication" by running and interacting with the app. This can include everything from simply monitoring network traffic or aspects of the app’s behavior to code injection, debugging, instrumentation, etc.] --

#### Remediation

-- TODO [Describe the best practices that developers should follow to prevent this issue "Testing 2-Factor Authentication".] --

#### References

##### OWASP Mobile Top 10 2016
* M4 - Insecure Authentication - https://www.owasp.org/index.php/Mobile_Top_10_2016-M4-Insecure_Authentication

##### OWASP MASVS
* 4.8: "A second factor of authentication exists at the remote endpoint and the 2FA requirement is consistently enforced."

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

-- TODO [Confirm remark on "Use the &lt;sup&gt; tag to reference external sources, e.g. Meyer's recipe for tomato soup<sup>[1]</sup>." ] --

-- TODO [Develop content on Testing Step-up Authentication with source code] --

#### Dynamic Analysis

-- TODO [Describe how to test for this issue "Testing Step-up Authentication" by running and interacting with the app. This can include everything from simply monitoring network traffic or aspects of the app’s behavior to code injection, debugging, instrumentation, etc.] --

#### Remediation

-- TODO [Describe the best practices that developers should follow to prevent this issue "Testing Step-up Authentication".] --

#### References

##### OWASP Mobile Top 10 2016
* M4 - Insecure Authentication - https://www.owasp.org/index.php/Mobile_Top_10_2016-M4-Insecure_Authentication

##### OWASP MASVS
* 4.9: "Step-up authentication is required to enable actions that deal with sensitive data or transactions."

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

-- TODO [Confirm remark on "Use the &lt;sup&gt; tag to reference external sources, e.g. Meyer's recipe for tomato soup<sup>[1]</sup>."] --

--TODO [Develop content on Testing User Device Management with source code] --


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
