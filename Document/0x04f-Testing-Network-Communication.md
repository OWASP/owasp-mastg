---
masvs_category: MASVS-NETWORK
platform: all
---

# Mobile App Network Communication

Almost every network-connected mobile app relies on the Hypertext Transfer Protocol (HTTP) or its secure version, HTTPS (which uses Transport Layer Security, TLS) to exchange data with remote endpoints. If not implemented securely, this communication can be vulnerable to network-based attacks such as packet sniffing and Machine-in-the-Middle (MITM) attacks. In this chapter, we explore potential vulnerabilities, testing techniques, and best practices for securing mobile app network communication.

## Secure Connections

The time has long passed since it was reasonable to use cleartext HTTP alone and it's usually trivial to secure HTTP connections using HTTPS. HTTPS is essentially HTTP layered on top of another protocol known as Transport Layer Security (TLS). And TLS performs a handshake using public key cryptography and, when complete, creates a secure connection.

An HTTPS connection is considered secure because of three properties:

- **Confidentiality:** TLS encrypts data before sending it over the network, which means it can't be read by an intermediary.
- **Integrity:** the data can't be altered without detection.
- **Authentication:** the client can validate the identity of the server to make sure the connection is established with the correct server.

## Server Trust Evaluation

Certificate Authorities (CAs) are an integral part of a secure client server communication and they are predefined in the trust store of each operating system. For instance, on iOS there are more than 200 root certificates installed (see [Apple documentation - Available trusted root certificates for Apple operating systems](https://support.apple.com/en-gb/HT204132 "Lists of available trusted root certificates in iOS"))

CAs can be added to the trust store, either manually by the user, by an MDM that manages the enterprise device or through malware. The question is then: "can you trust all of those CAs and should your app rely on the default trust store?". After all, there are well-known cases where certificate authorities have been compromised or tricked into issuing certificates to impostors. A detailed timeline of CA breaches and failures can be found at [sslmate.com](https://sslmate.com/certspotter/failures "Timeline of PKI Security Failures").

Both Android and iOS allow the user to install additional CAs or trust anchors.

An app may want to trust a custom set of CAs instead of the platform default. The most common reasons for this are:

- Connecting to a host with a custom certificate authority (a CA that isn't known or trusted by the system yet), such as a CA that is self-signed or is issued internally within a company.
- Limiting the set of CAs to a specific list of trusted CAs.
- Trusting additional CAs not included in the system.

### About Trust Stores

### Extending Trust

Whenever the app connects to a server whose certificate is self-signed or unknown to the system, the secure connection will fail. This is typically the case for any non public CAs, for instance those issued by an organization such as a government, corporation, or education institution for their own use.

Both Android and iOS offer means to extend trust, i.e. include additional CAs so that the app trusts the system's built-in ones plus the custom ones.

However, remember that the device users are always able to include additional CAs. Therefore, depending on the threat model of the app it might be necessary to avoid trusting any certificates added to the user trust store or even go further and only trust a pre-defined specific certificate or set of certificates.

For many apps, the "default behavior" provided by the mobile platform will be secure enough for their use case (in the rare case that a system-trusted CA is compromised the data handled by the app is not considered sensitive or other security measures are taken which are resilient even to such a CA breach). However, for other apps such as financial or health apps, the risk of a CA breach, even if rare, must be considered.

### Restricting Trust: Identity Pinning

Some apps might need to further increase their security by restricting the number of CAs that they trust. Typically only the CAs which are used by the developer are explicitly trusted, while disregarding all others. This trust restriction is known as _Identity Pinning_ usually implemented as _Certificate Pinning_ or _Public Key Pinning_.

> In the OWASP MASTG we will be referring to this term as "Identity Pinning", "Certificate Pinning", "Public Key Pinning" or simply "Pinning".

Pinning is the process of associating a remote endpoint with a particular identity, such as a X.509 certificate or public key, instead of accepting any certificate signed by a trusted CA. After pinning the server identity (or a certain set, aka. _pinset_), the mobile app will subsequently connect to those remote endpoints only if the identity matches. Withdrawing trust from unnecessary CAs reduces the app's attack surface.

#### General Guidelines

The [OWASP Certificate Pinning Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Pinning_Cheat_Sheet.html) gives essential guidance on:

- when pinning is recommended and which exceptions might apply.
- when to pin: development time (preloading) or upon first encountering (trust on first use).
- what to pin: certificate, public key or hash.

Both Android and iOS recommendations match the "best case" which is:

- Pin only to remote endpoints where the developer has control.
- at development time via (NSC/ATS)
- pin a hash of the SPKI `subjectPublicKeyInfo`.

Pinning has gained a bad reputation since its introduction several years ago. We'd like to clarify a couple of points that are valid at least for mobile application security:

- The bad reputation is due to operational reasons (e.g. implementation/pin management complexity) not lack of security.
- If an app does not implement pinning, this shouldn't be reported as a vulnerability. However, if the app must verify against MAS-L2 it must be implemented.
- Both Android and iOS make implementing pinning very easy and follow the best practices.
- Pinning protects against a compromised CA or a malicious CA that is installed on the device. In those cases, pinning will prevent the OS from establishing a secure connection from being established with a malicious server. However, if an attacker is in control of the device, they can easily disable any pinning logic and thus still allow the connection to happen. As a result, this will not prevent an attacker from accessing your backend and abusing server-side vulnerabilities.
- Pinning in mobile apps is not the same as HTTP Public Key Pinning (HPKP). The HPKP header is no longer recommended on websites as it can lead to users being locked out of the website without any way to revert the lockout. For mobile apps, this is not an issue, as the app can always be updated via an out-of-band channel (i.e. the app store) in case there are any issues.

#### About Pinning Recommendations in Android Developers

The [Android Developers](https://developer.android.com/training/articles/security-ssl#Pinning) site includes the following warning:

> Caution: Certificate Pinning is not recommended for Android applications due to the high risk of future server configuration changes, such as changing to another Certificate Authority, rendering the application unable to connect to the server without receiving a client software update.

They also include this [note](https://developer.android.com/training/articles/security-config#CertificatePinning):

> Note that, when using certificate pinning, you should always include a backup key so that if you are forced to switch to new keys or change CAs (when pinning to a CA certificate or an intermediate of that CA), your app's connectivity is unaffected. Otherwise, you must push out an update to the app to restore connectivity.

The first statement can be mistakenly interpreted as saying that they "do not recommend certificate pinning". The second statement clarifies this: the actual recommendation is that if developers want to implement pinning they have to take the necessary precautions.

#### About Pinning Recommendations in Apple Developers

Apple recommends [thinking long-term](https://developer.apple.com/news/?id=g9ejcf8y) and [creating a proper server authentication strategy](https://developer.apple.com/documentation/foundation/url_loading_system/handling_an_authentication_challenge/performing_manual_server_trust_authentication#2956135).

#### OWASP MASTG Recommendation

Pinning is a recommended practice, especially for MAS-L2 apps. However, developers must implement it exclusively for the endpoints under their control and be sure to include backup keys (aka. backup pins) and have a proper app update strategy.

#### Learn more

- ["Android Security: SSL Pinning"](https://appmattus.medium.com/android-security-ssl-pinning-1db8acb6621e)
- [OWASP Certificate Pinning Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Pinning_Cheat_Sheet.html)

## Verifying the TLS Settings

One of the core mobile app functions is sending/receiving data over untrusted networks like the Internet. If the data is not properly protected in transit, an attacker with access to any part of the network infrastructure (e.g., a Wi-Fi access point) may intercept, read, or modify it. This is why plaintext network protocols are rarely advisable.

The vast majority of apps rely on HTTP for communication with the backend. HTTPS wraps HTTP in an encrypted connection (the acronym HTTPS originally referred to HTTP over Secure Socket Layer (SSL); SSL is the deprecated predecessor of TLS). TLS allows authentication of the backend service and ensures confidentiality and integrity of the network data.

### Recommended TLS Settings

Ensuring proper TLS configuration on the server side is also important. The SSL protocol is deprecated and should no longer be used.
Also TLS v1.0 and TLS v1.1 have [known vulnerabilities](https://portswigger.net/daily-swig/the-end-is-nigh-browser-makers-ditch-support-for-aging-tls-1-0-1-1-protocols "Browser-makers ditch support for aging TLS 1.0, 1.1 protocols") and their usage is deprecated in all major browsers by 2020.
TLS v1.2 and TLS v1.3 are considered best practice for secure transmission of data. Starting with Android 10 (API level 29) TLS v1.3 will be enabled by default for faster and secure communication. The [major change with TLS v1.3](https://developer.android.com/about/versions/10/behavior-changes-all#tls-1.3 "TLS 1.3 enabled by default") is that customizing cipher suites is no longer possible and that all of them are enabled when TLS v1.3 is enabled, whereas Zero Round Trip (0-RTT) mode isn't supported.

When both the client and server are controlled by the same organization and used only for communicating with one another, you can increase security by [hardening the configuration](https://github.com/ssllabs/research/wiki/SSL-and-TLS-Deployment-Best-Practices "Qualys SSL/TLS Deployment Best Practices").

If a mobile application connects to a specific server, its networking stack can be tuned to ensure the highest possible security level for the server's configuration. Lack of support in the underlying operating system may force the mobile application to use a weaker configuration.

### Cipher Suites Terminology

Cipher suites have the following structure:

```txt
Protocol_KeyExchangeAlgorithm_WITH_BlockCipher_IntegrityCheckAlgorithm
```

This structure includes:

- A **Protocol** used by the cipher
- A **Key Exchange Algorithm** used by the server and the client to authenticate during the TLS handshake
- A **Block Cipher** used to encrypt the message stream
- A **Integrity Check Algorithm** used to authenticate messages

Example: `TLS_RSA_WITH_3DES_EDE_CBC_SHA`

In the example above the cipher suites uses:

- TLS as protocol
- RSA Asymmetric encryption for Authentication
- 3DES for Symmetric encryption with EDE_CBC mode
- SHA Hash algorithm for integrity

Note that in TLSv1.3 the Key Exchange Algorithm is not part of the cipher suite, instead it is determined during the TLS handshake.

In the following listing, we'll present the different algorithms of each part of the cipher suite.

**Protocols:**

- `SSLv1`
- `SSLv2` - [RFC 6176](https://tools.ietf.org/html/rfc6176 "RFC 6176")
- `SSLv3` - [RFC 6101](https://tools.ietf.org/html/rfc6101 "RFC 6101")
- `TLSv1.0` - [RFC 2246](https://tools.ietf.org/rfc/rfc2246 "RFC 2246")
- `TLSv1.1` - [RFC 4346](https://tools.ietf.org/html/rfc4346 "RFC 4346")
- `TLSv1.2` - [RFC 5246](https://tools.ietf.org/html/rfc5246 "RFC 5246")
- `TLSv1.3` - [RFC 8446](https://tools.ietf.org/html/rfc8446 "RFC 8446")

**Key Exchange Algorithms:**

- `DSA` - [RFC 6979](https://tools.ietf.org/html/rfc6979 "RFC 6979")
- `ECDSA` - [RFC 6979](https://tools.ietf.org/html/rfc6979 "RFC 6979")
- `RSA` - [RFC 8017](https://tools.ietf.org/html/rfc8017 "RFC 8017")
- `DHE` - [RFC 2631](https://tools.ietf.org/html/rfc2631 "RFC 2631") - [RFC 7919](https://tools.ietf.org/html/rfc7919 "RFC 7919")
- `ECDHE` - [RFC 4492](https://tools.ietf.org/html/rfc4492 "RFC 4492")
- `PSK` - [RFC 4279](https://tools.ietf.org/html/rfc4279 "RFC 4279")
- `DSS` - [FIPS186-4](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-4.pdf "FIPS186-4")
- `DH_anon` - [RFC 2631](https://tools.ietf.org/html/rfc2631 "RFC 2631") - [RFC 7919](https://tools.ietf.org/html/rfc7919 "RFC 7919")
- `DHE_RSA` - [RFC 2631](https://tools.ietf.org/html/rfc2631 "RFC 2631") - [RFC 7919](https://tools.ietf.org/html/rfc7919 "RFC 7919")
- `DHE_DSS` - [RFC 2631](https://tools.ietf.org/html/rfc2631 "RFC 2631") - [RFC 7919](https://tools.ietf.org/html/rfc7919 "RFC 7919")
- `ECDHE_ECDSA` - [RFC 8422](https://tools.ietf.org/html/rfc8422 "RFC 8422")
- `ECDHE_PSK`  - [RFC 8422](https://tools.ietf.org/html/rfc8422 "RFC 8422") - [RFC 5489](https://tools.ietf.org/html/rfc5489 "RFC 5489")
- `ECDHE_RSA`  - [RFC 8422](https://tools.ietf.org/html/rfc8422 "RFC 8422")

**Block Ciphers:**

- `DES`  - [RFC 4772](https://tools.ietf.org/html/rfc4772 "RFC 4772")
- `DES_CBC`  - [RFC 1829](https://tools.ietf.org/html/rfc1829 "RFC 1829")
- `3DES`  - [RFC 2420](https://tools.ietf.org/html/rfc2420 "RFC 2420")
- `3DES_EDE_CBC` - [RFC 2420](https://tools.ietf.org/html/rfc2420 "RFC 2420")
- `AES_128_CBC` - [RFC 3268](https://tools.ietf.org/html/rfc3268 "RFC 3268")
- `AES_128_GCM`  - [RFC 5288](https://tools.ietf.org/html/rfc5288 "RFC 5288")
- `AES_256_CBC` - [RFC 3268](https://tools.ietf.org/html/rfc3268 "RFC 3268")
- `AES_256_GCM` - [RFC 5288](https://tools.ietf.org/html/rfc5288 "RFC 5288")
- `RC4_40`  - [RFC 7465](https://tools.ietf.org/html/rfc7465 "RFC 7465")
- `RC4_128`  - [RFC 7465](https://tools.ietf.org/html/rfc7465 "RFC 7465")
- `CHACHA20_POLY1305`  - [RFC 7905](https://tools.ietf.org/html/rfc7905 "RFC 7905") - [RFC 7539](https://tools.ietf.org/html/rfc7539 "RFC 7539")

**Integrity Check Algorithms:**

- `MD5`  - [RFC 6151](https://tools.ietf.org/html/rfc6151 "RFC 6151")
- `SHA`  - [RFC 6234](https://tools.ietf.org/html/rfc6234 "RFC 6234")
- `SHA256`  - [RFC 6234](https://tools.ietf.org/html/rfc6234 "RFC 6234")
- `SHA384`  - [RFC 6234](https://tools.ietf.org/html/rfc6234 "RFC 6234")

Note that the efficiency of a cipher suite depends on the efficiency of its algorithms.

The following resources contain the latest recommended cipher suites to use with TLS:

- IANA recommended cipher suites can be found in [TLS Cipher Suites](https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-4 "TLS Cipher Suites").
- OWASP recommended cipher suites can be found in the [TLS Cipher String Cheat Sheet](https://github.com/OWASP/CheatSheetSeries/blob/master/cheatsheets/TLS_Cipher_String_Cheat_Sheet.md "OWASP TLS Cipher String Cheat Sheet").

Some Android and iOS versions do not support some of the recommended cipher suites, so for compatibility purposes you can check the supported cipher suites for [Android](https://developer.android.com/reference/javax/net/ssl/SSLSocket#cipher-suites "Cipher suites") and [iOS](https://developer.apple.com/documentation/security/1550981-ssl_cipher_suite_values?language=objc "SSL Cipher Suite Values") versions and choose the top supported cipher suites.

If you want to verify whether your server supports the right cipher suites, there are various tools you can use:

- nscurl - see [iOS Network Communication](0x06g-Testing-Network-Communication.md) for more details.
- [testssl.sh](https://github.com/drwetter/testssl.sh "testssl.sh") which "is a free command line tool which checks a server's service on any port for the support of TLS/SSL ciphers, protocols as well as some cryptographic flaws".

Finally, verify that the server or termination proxy at which the HTTPS connection terminates is configured according to best practices. See also the [OWASP Transport Layer Protection cheat sheet](https://github.com/OWASP/CheatSheetSeries/blob/master/cheatsheets/Transport_Layer_Protection_Cheat_Sheet.md "Transport Layer Protection Cheat Sheet") and the [Qualys SSL/TLS Deployment Best Practices](https://github.com/ssllabs/research/wiki/SSL-and-TLS-Deployment-Best-Practices "Qualys SSL/TLS Deployment Best Practices").

## Intercepting Network Traffic Through MITM

Intercepting mobile app traffic is a critical aspect of security testing, enabling testers, analysts, or penetration testers to analyze and manipulate network communications to identify vulnerabilities. A key technique in this process is the **Machine-in-the-Middle (MITM)** attack (also known as ["Man-in-the-Middle"](https://en.wikipedia.org/wiki/Man-in-the-middle_attack) (traditionally), "Adversary-in-the-Middle" (e.g. by [MITRE](https://attack.mitre.org/techniques/T1638/) and [CAPEC](https://capec.mitre.org/data/definitions/94.html)), etc.), where the _attacker_ positions their machine between two communicating entities, typically the mobile app (client) and the servers it is communicating with. By doing so, the attacker's machine intercepts and monitors the data being transmitted between the different parties.

This technique is twofold:

- Typically **used by malicious attackers** to intercept, monitor, and potentially alter the communication without either party (app or server) being aware. This allows for malicious activities such as eavesdropping, injecting malicious content, or manipulating the data being exchanged.
- However, **in the context of the OWASP MASTG** and mobile app security testing, we use it as part of our techniques to allow the app tester to review, analyze, or modify the traffic to identify vulnerabilities such as unencrypted communication or weak security controls.

The specific interception method used depends on the app's security mechanisms and the nature of the data being transmitted. Each approach varies in complexity and effectiveness, depending on factors such as encryption and the app's ability to resist interference.

Here's an overview of interception techniques at different network layers:

| **Interception Technique** | **Example Tools** | **Note** |
|---------------------------|-------------------|-------------------|
| API hooking (`HttpUrlConnection`, `NSURLSession`, `WebRequest`) | Frida | Modifies how apps handle network requests. |
| Hooking TLS functions (`SSL_read`, `SSL_write`) | Frida, SSL Kill Switch | Intercepts encrypted data before it reaches the app. |
| Proxy interception | Burp Suite, ZAP, mitmproxy | Requires app to respect proxy settings. |
| Packet sniffing | `tcpdump`, Wireshark | Captures **all** TCP/UDP traffic but does **not** decrypt HTTPS. |
| MITM via ARP spoofing | bettercap | Tricks devices into sending their traffic through the attacker's machine even when the network isn't controlled by the attacker. |
| Rogue Wi-Fi AP | `hostapd`, `dnsmasq`, `iptables`, `wpa_supplicant`, `airmon-ng` | Uses an access point fully controlled by the attacker. |

You can find more information on these techniques in their corresponding technique pages:

- @MASTG-TECH-0119
- @MASTG-TECH-0120
- @MASTG-TECH-0121
- @MASTG-TECH-0122
- @MASTG-TECH-0123
- @MASTG-TECH-0124

**Note about certificate pinning:** If the app uses certificate pinning, the techniques above may seem to fail once you start intercepting the traffic, but you can bypass it using different methods. See the following techniques for more information:

- Android: @MASTG-TECH-0012
- iOS: @MASTG-TECH-0064
