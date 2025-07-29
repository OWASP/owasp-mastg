---
masvs_category: MASVS-STORAGE
platform: android
title: Key Attestation
available_since: 24
---

For the applications which heavily rely on Android Keystore for business-critical operations, such as multi-factor authentication through cryptographic primitives, secure storage of sensitive data at the client-side, etc. Android provides the feature of [Key Attestation](https://developer.android.com/training/articles/security-key-attestation "Key Attestation"), which helps to analyze the security of cryptographic material managed through Android Keystore. From Android 8.0 (API level 26), the key attestation was made mandatory for all new (Android 7.0 or higher) devices that need to have device certification for Google apps. Such devices use attestation keys signed by the [Google hardware Attestation Root certificate](https://developer.android.com/training/articles/security-key-attestation#root_certificate "Google Hardware Attestation Root Certificate") and the same can be verified through the key attestation process.

During key attestation, we can specify the alias of a key pair and in return, get a certificate chain, which we can use to verify the properties of that key pair. If the root certificate of the chain is the [Google Hardware Attestation Root certificate](https://developer.android.com/training/articles/security-key-attestation#root_certificate "Google Hardware Attestation Root certificate"), and the checks related to key pair storage in hardware are made, it gives an assurance that the device supports hardware-level key attestation, and that the key is in the hardware-backed keystore that Google believes to be secure. Alternatively, if the attestation chain has any other root certificate, then Google does not make any claims about the security of the hardware.

Although the key attestation process can be implemented within the application directly, it is recommended that it should be implemented at the server-side for security reasons. The following are the high-level guidelines for the secure implementation of Key Attestation:

- The server should initiate the key attestation process by creating a random number securely using CSPRNG (Cryptographically Secure Random Number Generator) and the same should be sent to the user as a challenge.
- The client should call the `setAttestationChallenge` API with the challenge received from the server and should then retrieve the attestation certificate chain using the `KeyStore.getCertificateChain` method.
- The attestation response should be sent to the server for the verification and following checks should be performed for the verification of the key attestation response:
    - Verify the certificate chain, up to the root and perform certificate sanity checks such as validity, integrity and trustworthiness. Check the [Certificate Revocation Status List](https://developer.android.com/training/articles/security-key-attestation#certificate_status "Certificate Revocation Status List") maintained by Google, if none of the certificates in the chain was revoked.
    - Check if the root certificate is signed with the Google attestation root key which makes the attestation process trustworthy.
    - Extract the attestation [certificate extension data](https://developer.android.com/training/articles/security-key-attestation#certificate_schema "Certificate extension data schema"), which appears within the first element of the certificate chain, and perform the following checks:
        - Verify that the attestation challenge is having the same value which was generated at the server while initiating the attestation process.
        - Verify the signature in the key attestation response.
        - Verify the security level of the Keymaster, to determine if the device has secure key storage mechanism. Keymaster is a piece of software that runs in the security context and provides all the secure keystore operations. The security level will be one of `Software`, `TrustedEnvironment` or `StrongBox`. The client supports hardware-level key attestation if the security level is `TrustedEnvironment` or `StrongBox` and the attestation certificate chain contains a root certificate signed with the Google attestation root key.
        - Verify the client's status to ensure a full chain of trust - verified boot key, locked bootloader and verified boot state.
        - Additionally, you can verify the key pair's attributes such as purpose, access time, authentication requirement, etc.

> Note, if for any reason that process fails, it means that the key is not in security hardware. That does not mean that the key is compromised.

The typical example of Android Keystore attestation response looks like this:

```json
{
    "fmt": "android-key",
    "authData": "9569088f1ecee3232954035dbd10d7cae391305a2751b559bb8fd7cbb229bd...",
    "attStmt": {
        "alg": -7,
        "sig": "304402202ca7a8cfb6299c4a073e7e022c57082a46c657e9e53...",
        "x5c": [
            "308202ca30820270a003020102020101300a06082a8648ce3d040302308188310b30090603550406130...",
            "308202783082021ea00302010202021001300a06082a8648ce3d040302308198310b300906035504061...",
            "3082028b30820232a003020102020900a2059ed10e435b57300a06082a8648ce3d040302308198310b3..."
        ]
    }
}
```

In the above JSON snippet, the keys have the following meaning:

- `fmt`: Attestation statement format identifier
- `authData`: It denotes the authenticator data for the attestation
- `alg`: The algorithm that is used for the Signature
- `sig`: Signature
- `x5c`: Attestation certificate chain

> Note: The `sig` is generated by concatenating `authData` and `clientDataHash` (challenge sent by the server) and signing through the credential private key using the `alg` signing algorithm. The same is verified at the server-side by using the public key in the first certificate.

For more understanding on the implementation guidelines, you can refer to [Google Sample Code](https://github.com/google/android-key-attestation/blob/master/src/main/java/com/android/example/KeyAttestationExample.java "Google Sample Code For Android Key Attestation").

For the security analysis perspective, the analysts may perform the following checks for the secure implementation of Key Attestation:

- Check if the key attestation is totally implemented on the client-side. In which case, it can be more easily bypassed by tampering the application, method hooking, etc.
- Check if the server uses random challenge while initiating the key attestation. As failing to do that would lead to insecure implementation thus making it vulnerable to replay attacks. Also, checks pertaining to the randomness of the challenge should be performed.
- Check if the server verifies the integrity of the key attestation response.
- Check if the server performs basic checks such as integrity verification, trust verification, validity, etc. on the certificates in the chain.
