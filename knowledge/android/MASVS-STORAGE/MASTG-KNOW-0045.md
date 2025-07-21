---
masvs_category: MASVS-STORAGE
platform: android
title: Secure Key Import into Keystore
---

Android 9 (API level 28) adds the ability to import keys securely into the `AndroidKeystore`. First, `AndroidKeystore` generates a key pair using `PURPOSE_WRAP_KEY`, which should also be protected with an attestation certificate. This pair aims to protect the Keys being imported to `AndroidKeystore`. The encrypted keys are generated as ASN.1-encoded message in the `SecureKeyWrapper` format, which also contains a description of the ways the imported key is allowed to be used. The keys are then decrypted inside the `AndroidKeystore` hardware belonging to the specific device that generated the wrapping key, so that they never appear as plaintext in the device's host memory.

<img src="Images/Chapters/0x05d/Android9_secure_key_import_to_keystore.jpg" alt="Secure key import into Keystore" width="500px"/>

Example in Java:

```java
KeyDescription ::= SEQUENCE {
    keyFormat INTEGER,
    authorizationList AuthorizationList
}

SecureKeyWrapper ::= SEQUENCE {
    wrapperFormatVersion INTEGER,
    encryptedTransportKey OCTET_STRING,
    initializationVector OCTET_STRING,
    keyDescription KeyDescription,
    secureKey OCTET_STRING,
    tag OCTET_STRING
}
```

The code above presents the different parameters to be set when generating the encrypted keys in the SecureKeyWrapper format. Check the Android documentation on [`WrappedKeyEntry`](https://developer.android.com/reference/android/security/keystore/WrappedKeyEntry "WrappedKeyEntry") for more details.

When defining the KeyDescription AuthorizationList, the following parameters will affect the encrypted keys security:

- The `algorithm` parameter specifies the cryptographic algorithm with which the key is used
- The `keySize` parameter specifies the size, in bits, of the key, measuring in the normal way for the key's algorithm
- The `digest` parameter specifies the digest algorithms that may be used with the key to perform signing and verification operations
