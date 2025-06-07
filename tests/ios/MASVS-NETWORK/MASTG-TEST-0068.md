---
masvs_v1_id:
- MSTG-NETWORK-4
masvs_v2_id:
- MASVS-NETWORK-2
platform: ios
title: Testing Custom Certificate Stores and Certificate Pinning
masvs_v1_levels:
- L2
profiles: [L2]
---

## Overview

## Static Analysis

Verify that the server certificate is pinned. Pinning can be implemented on various levels in terms of the certificate tree presented by the server:

1. Including server's certificate in the application bundle and performing verification on each connection. This requires an update mechanisms whenever the certificate on the server is updated.
2. Limiting certificate issuer to e.g. one entity and bundling the intermediate CA's public key into the application. In this way we limit the attack surface and have a valid certificate.
3. Owning and managing your own PKI. The application would contain the intermediate CA's public key. This avoids updating the application every time you change the certificate on the server, due to e.g. expiration. Note that using your own CA would cause the certificate to be self-singed.

The latest approach recommended by Apple is to specify a pinned CA public key in the `Info.plist` file under App Transport Security Settings. You can find an example in their article [Identity Pinning: How to configure server certificates for your app](https://developer.apple.com/news/?id=g9ejcf8y "Identity Pinning: How to configure server certificates for your app").

Another common approach is to use the [`connection:willSendRequestForAuthenticationChallenge:`](https://developer.apple.com/documentation/foundation/nsurlconnectiondelegate/1414078-connection?language=objc "connection:willSendRequestForAuthenticationChallenge:") method of `NSURLConnectionDelegate` to check if the certificate provided by the server is valid and matches the certificate stored in the app. You can find more details in the [HTTPS Server Trust Evaluation](https://developer.apple.com/library/archive/technotes/tn2232/_index.html#//apple_ref/doc/uid/DTS40012884-CH1-SECNSURLCONNECTION "HTTPS Server Trust Evaluation") technical note.

The following third-party libraries include pinning functionality:

- [TrustKit](https://github.com/datatheorem/TrustKit "TrustKit"): here you can pin by setting the public key hashes in your Info.plist or provide the hashes in a dictionary. See their README for more details.
- [AlamoFire](https://github.com/Alamofire/Alamofire "AlamoFire"): here you can define a `ServerTrustPolicy` per domain for which you can define a `PinnedCertificatesTrustEvaluator`. See its [documentation](https://github.com/Alamofire/Alamofire/blob/master/Documentation/AdvancedUsage.md#security) for more details.
- [AFNetworking](https://github.com/AFNetworking/AFNetworking "AfNetworking"): here you can set an `AFSecurityPolicy` to configure your pinning.

## Dynamic Analysis

### Server certificate pinning

Follow the instructions from the Dynamic Analysis section of @MASTG-TEST-0067. If doing so doesn't lead to traffic being proxied, it may mean that certificate pinning is actually implemented and all security measures are in place. Does the same happen for all domains?

As a quick smoke test, you can try to bypass certificate pinning using @MASTG-TOOL-0038 as described in @MASTG-TECH-0064. Pinning related APIs being hooked by objection should appear in objection's output.

<img src="Images/Chapters/0x06b/ios_ssl_pinning_bypass.png" width="100%" />

However, keep in mind that:

- the APIs might not be complete.
- if nothing is hooked, that doesn't necessarily mean that the app doesn't implement pinning.

In both cases, the app or some of its components might implement custom pinning in a way that is [supported by objection](https://github.com/sensepost/objection/blob/master/agent/src/ios/pinning.ts). Please check the static analysis section for specific pinning indicators and more in-depth testing.

### Client certificate validation

Some applications use mTLS (mutual TLS), meaning that the application verifies the server's certificate and the server verifies the client's certificate. You can notice this if there is an error in Burp **Alerts** tab indicating that client failed to negotiate connection.

There are a couple of things worth noting:

1. The client certificate contains a private key that will be used for the key exchange.
2. Usually the certificate would also need a password to use (decrypt) it.
3. The certificate can be stored in the binary itself, data directory or in the Keychain.

The most common and improper way of using mTLS is to store the client certificate within the application bundle and hardcode the password. This obviously does not bring much security, because all clients will share the same certificate.

Second way of storing the certificate (and possibly password) is to use the Keychain. Upon first login, the application should download the personal certificate and store it securely in the Keychain.

Sometimes applications have one certificate that is hardcoded and use it for the first login and then the personal certificate is downloaded. In this case, check if it's possible to still use the 'generic' certificate to connect to the server.

Once you have extracted the certificate from the application (e.g. using Frida), add it as client certificate in Burp, and you will be able to intercept the traffic.
