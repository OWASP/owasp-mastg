## Testing Local Authentication in iOS Apps

During local authentication, an app authenticates the user against credentials stored locally on the device. In other words, the user "unlocks" the app or some inner layer of functionality by providing a valid PIN, password, or fingerprint, verified by referencing local data. Generally, this process is invoked for reasons such providing a user convenience for resuming an existing session with the remote service or as a means of step-up authentication to protect some critical function.

### Testing Local Authentication

#### Overview

On iOS, a variety of methods are available for integrating local authentication into apps. The [Local Authentication framework](https://developer.apple.com/documentation/localauthentication) provides a set of APIs for developers to extend an authentication dialog to a user. In the context of connecting to a remote service, it is possible (and recommended) to leverage the [Keychain]( https://developer.apple.com/library/content/documentation/Security/Conceptual/keychainServConcepts/01introduction/introduction.html) for implementing local authentication.

##### Local Authentication Framework

The Local Authentication framework provides facilities for requesting a passphrase or TouchID authentication from users. This enables developers to display and utilize an authentication prompt by utilizing the function <code>evaluatePolicy</code> of the <code>LAContext</code> object. 

Two available policies define acceptable forms of authentication:

- LAPolicyDeviceOwnerAuthentication: When available, the user is prompted to perform TouchID authentication. If TouchID is not activated, the device passcode is requested instead. If the device passcode is not enabled, policy evaluation fails.

- LAPolicyDeviceOwnerAuthenticationWithBiometrics: Authentication is restricted to biometrics where user the is prompted for TouchID.

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

The iOS Keychain APIs can (and should) be used to implement local authentication. During this process, the app requests either a secret authentication token or another piece of secret data identifying the user stored by the Keychain. In order to authenticate a remote service, the user must unlock the Keychain using their passphrase or fingerprint to obtain the secret data. 

The Keychain mechanism is explained in greater detail within an earlier chapter, "Testing Data Storage".

#### Static Analysis

It is important to remember Local Authentication framework is an event-based procedure and as such, should not the sole method for determining valid authentication. Though this type of authentication is effective on the user-interface level, it is easily bypassed through patching or instrumentation.

When testing local authentication on iOS, ensure sensitive flows are protected using the Keychain services method. For example, some apps resume an existing user session with TouchID authentication. In these cases, session credentials or tokens (e.g. refresh tokens) should be securely stored in the Keychain (as described above) as well as "locked" with local authentication.

#### Dynamic Analysis

If a potential local authentication bypass issue is discovered, it is likely exploitable by patching the app or using <code>Cycript</code> as an instrument to modify the process. How to do this is explained in greater detail during the "Reverse Engineering and Tampering" chapter.

#### Remediation

The Local Authentication framework makes adding either TouchID or similar authentication a simple procedure. More sensitive processes, such as re-authenticating a user using a remote payment service with this method, is strongly discouraged. Instead, the best approach for handling local authentication in these scenarios involves utilizing Keychain to store a user secret (e.g. refresh token). This task may be accomplished as follows:

- Use the <code>SecAccessControlCreateWithFlags()</code> to call a security access control reference. Specify the <code>kSecAccessControlUserPresence</code> policy and <code>kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly</code> protection class.

- Insert the data using the returned <code>SecAccessControlRef</code> value into the attributes dictionary.

#### References

##### OWASP Mobile Top 10 2016

- M4 - Insecure Authentication - https://www.owasp.org/index.php/Mobile_Top_10_2016-M4-Insecure_Authentication

##### OWASP MASVS

- V4.7: "Biometric authentication, if any, is not event-bound (i.e. using an API that simply returns "true" or "false"). Instead, it is based on unlocking the keychain/keystore."

##### CWE

- CWE-287 - Improper Authentication
