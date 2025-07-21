---
masvs_category: MASVS-AUTH
platform: ios
---

# iOS Local Authentication

## Overview

During local authentication, an app authenticates the user against credentials stored locally on the device. In other words, the user "unlocks" the app or some inner layer of functionality by providing a valid PIN, password or biometric characteristics such as face or fingerprint, which is verified by referencing local data. Generally, this is done so that users can more conveniently resume an existing session with a remote service or as a means of step-up authentication to protect some critical function.

As stated before in chapter ["Mobile App Authentication Architectures"](0x04e-Testing-Authentication-and-Session-Management.md): The tester should be aware that local authentication should always be enforced at a remote endpoint or based on a cryptographic primitive. Attackers can easily bypass local authentication if no data returns from the authentication process.

A variety of methods are available for integrating local authentication into apps. The [Local Authentication framework](https://developer.apple.com/documentation/localauthentication "Local Authentication framework") provides a set of APIs for developers to extend an authentication dialog to a user. In the context of connecting to a remote service, it is possible (and recommended) to leverage the [keychain](https://developer.apple.com/library/content/documentation/Security/Conceptual/keychainServConcepts/01introduction/introduction.html "Keychain Services") for implementing local authentication.

Fingerprint authentication on iOS is known as _Touch ID_. The fingerprint ID sensor is operated by the [SecureEnclave security coprocessor](https://www.blackhat.com/docs/us-16/materials/us-16-Mandt-Demystifying-The-Secure-Enclave-Processor.pdf "Demystifying the Secure Enclave Processor by Tarjei Mandt, Mathew Solnik, and David Wang") and does not expose fingerprint data to any other parts of the system. Next to Touch ID, Apple introduced _Face ID_: which allows authentication based on facial recognition. Both use similar APIs on an application level, the actual method of storing the data and retrieving the data (e.g. facial data or fingerprint related data is different).

Developers have two options for incorporating Touch ID/Face ID authentication:

- `LocalAuthentication.framework` is a high-level API that can be used to authenticate the user via Touch ID. The app can't access any data associated with the enrolled fingerprint and is notified only whether authentication was successful.
- `Security.framework` is a lower level API to access [keychain services](https://developer.apple.com/documentation/security/keychain_services "keychain Services"). This is a secure option if your app needs to protect some secret data with biometric authentication, since the access control is managed on a system-level and can not easily be bypassed. `Security.framework` has a C API, but there are several [open source wrappers available](https://www.raywenderlich.com/147308/secure-ios-user-data-keychain-touch-id "How To Secure iOS User Data: The keychain and Touch ID"), making access to the keychain as simple as to NSUserDefaults. `Security.framework` underlies `LocalAuthentication.framework`; Apple recommends to default to higher-level APIs whenever possible.

Please be aware that using either the `LocalAuthentication.framework` or the `Security.framework`, will be a control that can be bypassed by an attacker as it does only return a boolean and no data to proceed with. See [Don't touch me that way, by David Lindner et al](https://www.youtube.com/watch?v=XhXIHVGCFFM "Don\'t Touch Me That Way - David Lindner") for more details.
