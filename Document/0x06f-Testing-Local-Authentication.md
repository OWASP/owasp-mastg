## Testing Local Authentication in iOS Apps

In local authentication, the app authenticates the user against credentials stored on the device itself. In other words, the user "unlocks" the app or some functionality within the app with a PIN, password or fingerprint that is verified only locally. This is sometimes done to allow users to more easily resume an existing session with the remote service, or as a means of step-up authentication to protect some critical functionality.

### Testing Local Authentication

#### Overview

On iOS, multiple possibilities exist for integrating local authentication into iOS apps. The [Local Authentication Framework](https://developer.apple.com/documentation/localauthentication) offers a set of APIs that display an authentication dialog to the user. In the context of connecting to a remote service, it is also possible (and recommended) to leverage the Keychain for implementing local authentication.

##### Local Authentication Framework

The Local Authentication Framework provides facilities for requesting a passphrase or TouchID authentication from users. With local authentication, an authentication prompt is displayed to the user programmatically using the function <code>evaluatePolicy</code> of the <code>LAContext</code> object.

Two policies are available that define the acceptable forms of authentication:

- LAPolicyDeviceOwnerAuthentication: The user is asked to perform TouchID authentication if available. If TouchID is not activated, they are asked to enter the device passcode. If the device passcode is not enabled, policy evaluation fails.

- LAPolicyDeviceOwnerAuthenticationWithBiometrics: The user is asked to perform TouchID authentication.

The <code>evaluatePolicy</code> function returns a boolean value indicating whether the user has authenticated successfully.

```
let myContext = LAContext()
let myLocalizedReasonString = <#String explaining why app needs authentication#>
 
var authError: NSError? = nil
if #available(iOS 8.0, OSX 10.12, *) {
    if myContext.canEvaluatePolicy(LAPolicy.DeviceOwnerAuthenticationWithBiometrics, error: &authError) {
        myContext.evaluatePolicy(LAPolicy.DeviceOwnerAuthenticationWithBiometrics, localizedReason: myLocalizedReasonString) { (success, evaluateError) in
            if (success) {
                // User authenticated successfully, take appropriate action
            } else {
                // User did not authenticate successfully, look at error and take appropriate action
            }
        }
    } else {
        // Could not evaluate policy; look at authError and present an appropriate message to user
    }
} else {
    // Fallback on earlier versions
}
```
*TouchID authentication using the Local Authentication Framework (official Apple code sample).* 

#####  Using Keychain Services for Local Authentication

The iOS Keychain APIs can be used to implement local authentication. In that case, some secret authentication token (or other piece of secret data identifying the user) is stored in the Keychain. This is commonly implemented by inserting the data into the Keychain using the <code>kSecAccessControlUserPresence</code> policy and a <code>kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly</code> protection class. In other to authenticate to the remote service, the user then needs to unlock the Keychain using their passphrase or fingerprint and obtain the secret data (the Keychain mechanism is explained in more detail in the chapter "Testing Data Storage").

#### Static Analysis

-- TODO [Confirm purpose of remark "Use the &lt;sup&gt; tag to reference external sources, e.g. Meyer's recipe for tomato soup<sup>[1]</sup>."] --

-- TODO [Add content for "Testing Biometric Authentication" with source code] --

#### Dynamic Analysis

-- TODO [Describe how to test for this issue "Testing Biometric Authentication" by running and interacting with the app. This can include everything from simply monitoring network traffic or aspects of the app’s behavior to code injection, debugging, instrumentation, etc.] --

#### Remediation

Example: https://www.raywenderlich.com/92667/securing-ios-data-keychain-touch-id-1password
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
