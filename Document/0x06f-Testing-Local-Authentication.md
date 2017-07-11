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

The iOS Keychain APIs can be used to implement local authentication. In that case, some secret authentication token (or other piece of secret data identifying the user) is stored in the Keychain. In other to authenticate to the remote service, the user then needs to unlock the Keychain using their passphrase or fingerprint and obtain the secret data (the Keychain mechanism is explained in more detail in the chapter "Testing Data Storage").

#### Static Analysis

A common mistake when using local authentication is putting to much trust into the purely event-based (Local Authentication Framework) implementation. This type of authentication is effective on the user interface level, but can easily be bypassed through patching or instrumentation.

If the app you are testing implements local authentication, make sure that sensitive flows are protected using the Keychain services method. For example, in some apps an existing user session can be resumed using TouchID authentication. In that case, make sure that the session credentials or tokens (e.g. refresh token) are stored securely in the Keychain as described above and "locked" with local authentication.

#### Dynamic Analysis

If you identify a potential local authentication bypass issue, you can exploit by patching the app or using Cycript to instrument it. We'll explain how to do this in the "Reverse Engineering and Tampering" chapter.

#### Remediation

The Local Authentication Framework makes it easy to add TouchID or similar authentication. For sensitive applications however, such as re-authenticating a user on a remote payment service, using the Local Authentication Framework is not recommended. Instead, the local authentication should be implemented by storing a user secret (e.g. refresh token) into the Keychain. This is done as follows:

- Use the <code>SecAccessControlCreateWithFlags()</code> API to obtain a security access control reference. Specify the <code>kSecAccessControlUserPresence</code> policy and <code>kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly</code> protection class.
- Inserting the data using the returned SecAccessControlRef in the attributes dictionary.

#### References

##### OWASP Mobile Top 10 2016

- M4 - Insecure Authentication - https://www.owasp.org/index.php/Mobile_Top_10_2016-M4-Insecure_Authentication

##### OWASP MASVS

- V4.7: "Biometric authentication, if any, is not event-bound (i.e. using an API that simply returns "true" or "false"). Instead, it is based on unlocking the keychain/keystore."

##### CWE

- CWE-287 - Improper Authentication
