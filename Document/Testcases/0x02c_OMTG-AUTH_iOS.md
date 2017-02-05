### <a name="[Anchor, e.g.: OMTG-DATAST-001]"></a>OMTG-AUTH-001:Test for Bypass Client Side Authentication
#### Overview
Some applications are doing the authentication relying on the client side, that means that the developer creates some method that will check the username and password on the client 
side instead of sending the credentials into the backend API.
So in that situation, it is possible with the help of some tools to bypass login forms and get access to the application
#### White-box Testing
For White-box Testing , you should identify any function in the source code that will check the credentials suplied by the user and then return true if its correct or false. 
#### Black-box Testing
The following steps can be applied to check if the application relies on client-side authentication from a point of view of Black-box Testing:

    1. Log into the iPhone jailbroken by ssh. 
    2. Then open the application and by executing “ps aux” look for the name of the application 
    and get the corresponding ID.
    3. Then execute class-dump-z tool and if is not encryped you will get the source code
    4. If it’s not possible to dump the source code of the binary that means that the binary is encrypted 
    so before executing the class-dump-z tool is important to execute the clutch2 tool for decrypt 
    the binary.
    5. Then with the tool cycript –p <App_ID> it’s possible to hook into the application methods.
    6. First, let’s find the root view controller by using this command: 
       cy#UIApp.keyWindow.rootViewController
       
    7. Since the login page is the first view to see in the application is possible to find 
    the current view by finding the visibleViewController property of the navigation controller.
    Now by using the property of an isa.message we can display all the messages for this ViewController.
    The method "ValidateLogin" is the one that can be interesting for us.
    8. As we can see,the method validateLogin returns a BOOL value.
    With Cycript, we can manipulate this function and make that always return true and 
    we can access to the application without knowing any valid credentials with the following
    command: 
    cy#ViewController.messages['ValidateLogin'] = function() {return true;}
    
    9. Also other way to bypass this authentication. From the class-dump-z output, 
    we can figure out that once validateLogin returns TRUE, the method pushLoginPage gets called.
    Some other names for such methods could have been pushUserPage, or pushLoginSuccessfulPage etc. 
    Well, we don’t need the validation to be true. We can always call this method ourselves.
    cy#[UIApp.keyWindow.rootViewController.visibleViewController pushLoginPage]   


#### Remediation
One of the most common errors done by developers is do the authentication mechanism relying on the client side.
For prevent that, once the application ask for username and password after we provide that, the credentials must be sent to a backend API, then the API Server validate the credentials and if it is correct will give back a valid jWT 
#### References:
- [1] http://resources.infosecinstitute.com/ios-application-security-part-8-method-swizzling-using-cycript/#gref
- [2] https://www.owasp.org/index.php/Mobile_Top_10_2014-M5

### <a name="[Anchor, e.g.: OMTG-DATAST-002]"></a>OMTG-AUTH-002:Testing the Logout Functionality
#### Overview
Session termination is an important part of the session lifecycle. Reducing the lifetime of the session tokens to a minimum decreases the likelihood of a successful session hijacking attack.
 
The scope for this test case is to validate that the application has a logout functionality and it effectively terminates the session on client and server side.
 
#### Testing
To verify the correct implementation of a logout functionality, dynamic analysis should be applied by using an interception proxy. This technique can be applied to both, Android and iOS platform.  
Static Analysis
If server side code is available, it should be reviewed to validate that the session is being terminated as part of the logout functionality.
The check needed here will be different depending on the technology used. Here are different examples on how a session can be terminated in order to implement a proper logout on server side:
- Spring (Java) - http://docs.spring.io/spring-security/site/docs/current/apidocs/org/springframework/security/web/authentication/logout/SecurityContextLogoutHandler.html
-	Ruby on Rails -  http://guides.rubyonrails.org/security.html
- PHP - http://php.net/manual/en/function.session-destroy.php
-	JSF - http://jsfcentral.com/listings/A20158?link
-	ASP.Net - https://msdn.microsoft.com/en-us/library/ms524798(v=vs.90).aspx
-	Amazon AWS - http://docs.aws.amazon.com/appstream/latest/developerguide/rest-api-session-terminate.html

#### Dynamic Analysis
For a dynamic analysis of the application an interception proxy should be used. Please see section XXX on how to set it up.
The following steps can be applied to check if the logout is implemented properly.  
1.	Log into the application.
2.	Do a couple of operations that require authentication inside the application.
3.	Perform a logout operation.
4.	Resend one of the operations detailed in step 2 using an interception proxy. For example, with Burp Repeater. The purpose of this is to send to the server a request with the token that has been invalidated in step 3.
 
If the session is correctly terminated on the server side, either an error message or redirect to the login page will be sent back to the client. On the other hand, if you have the same response you had in step 2, then, this session is still valid and has not been correctly terminated on the server side.
A detailed explanation with more test cases, can also be found in the OWASP Web Testing Guide (OTG-SESS-006) [1].

#### Remediation 
One of the most common errors done by developers to a logout functionality is simply not destroying the session object in the server side. This leads to a state where the session is still alive even though the user logs out of the application. The session remains alive, and if an attacker get’s in possession of a valid session he can still use it and a user cannot even protect himself by logging out or if there are no session timeout controls in place.
 
To mitigate it, the logout function on the server side must invalidate this session identifier immediately after logging out to prevent it to be reused by an attacker that could have intercepted it.
 
Related to this, it must be checked that after calling an operation with an expired token, the application does not generate another valid token. This could lead to another authentication bypass.
 
Many Apps do not automatically logout a user, because of customer convenience. The user logs in once, afterwards a token is generated on server side and stored within the applications internal storage and used for authentication when the application starts instead of asking again for user credentials. There should still be a logout function available within the application and this should work according to best practices by also destroying the session on server side.

#### References
- [1] https://www.owasp.org/index.php/Testing_for_logout_functionality_(OTG-SESS-006)
- [2] https://www.owasp.org/index.php/Session_Management_Cheat_Sheet

### <a name="[Anchor, e.g.: OMTG-DATAST-003]"></a>OMTG-AUTH-003:Testing the Session Timeout
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
- 	Ruby on Rails -  https://github.com/rails/rails/blob/318a20c140de57a7d5f820753c82258a3696c465/railties/lib/rails/application/configuration.rb#L130
- PHP - http://php.net/manual/en/session.configuration.php#ini.session.gc-maxlifetime
- ASP.Net - https://msdn.microsoft.com/en-GB/library/system.web.sessionstate.httpsessionstate.timeout(v=vs.110).aspx
-	Amazon AWS - http://docs.aws.amazon.com/ElasticLoadBalancing/latest/DeveloperGuide/config-idle-timeout.html
 
Some applications also have an autologoff functionality in the client side. This is not a mandatory feature, but helps to improve to enforce a session timeout.  To implement this, the client side needs to control the timestamp when the screen has been displayed, and check continuously if the time elapsed is lower than the defined timeout. Once that time matches or excesses the timeout, the logoff method will be invoked, sending a signal to the server side to terminate the session and redirecting the customer to an informative screen.
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
-	Log into the application.
-	Do a couple of operations that require authentication inside the application.
-	Leave the application in idle until the session expires (for testing purposes, a reasonable timeout can be configured, and amended later in the final version)
 
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
- [1] OWASP web application test guide https://www.owasp.org/index.php/Test_Session_Timeout_(OTG-SESS-007)
- [2] OWASP Session management cheatsheet https://www.owasp.org/index.php/Session_Management_Cheat_Sheet

### <a name="[Anchor, e.g.: OMTG-DATAST-004]"></a>OMTG-AUTH-004:Testing Excessive Login Attempts
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
1.	Log in incorrectly for a number of times to trigger the lockout control (generally 3 to 15 incorrect attempts)
2.	Once you have locked out the account, enter the correct logon details to verify if login is not possible anymore.
If this is correctly implemented, when the right password is entered, logon should be denied, as the credential has already been blocked.

#### Remediation
Lockout controls have to be implemented to prevent brute force attacks. See [3] for further mitigation techniques.
It is interesting to clarify that incorrect logon attempts should be cumulative and not linked to a session. If you implement a control to block the credential in your 3rd attempt in the same session, it can be easily bypassed by entering the details wrong two times and get a new session. This will then give another free attempts.

#### References
- [1] https://www.owasp.org/index.php/Testing_for_Weak_lock_out_mechanism_(OTG-AUTHN-003)
- [2] https://www.owasp.org/index.php/Brute_force_attack
- [3] https://www.owasp.org/index.php/Blocking_Brute_Force_Attacks

