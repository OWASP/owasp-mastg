# Mobile App Network Communication

Practically every network-connected mobile app uses the Hypertext Transfer Protocol (HTTP) or HTTP over Transport Layer Security (TLS), HTTPS, to send and receive data to and from remote endpoints. Consequently, network-based attacks (such as packet sniffing and man-in-the-middle-attacks) are a problem. In this chapter we discuss potential vulnerabilities, testing techniques, and best practices concerning the network communication between mobile apps and their endpoints.

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
- If an app does not implement pinning, this shouldn't be reported as a vulnerability. However, if the app must verify against MASVS-L2 it must be implemented.
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

Pinning is a recommended practice, especially for MASVS-L2 apps. However, developers must implement it exclusively for the endpoints under their control and be sure to include backup keys (aka. backup pins) and have a proper app update strategy.

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

When both the client and server are controlled by the same organization and used only for communicating with one another, you can increase security by [hardening the configuration](https://dev.ssllabs.com/projects/best-practices/ "Qualys SSL/TLS Deployment Best Practices").

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

In the following listing, we’ll present the different algorithms of each part of the cipher suite.

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
- `DHE` - [RFC 2631](https://tools.ietf.org/html/rfc2631 "RFC 2631")  - [RFC 7919](https://tools.ietf.org/html/rfc7919 "RFC 7919")
- `ECDHE` - [RFC 4492](https://tools.ietf.org/html/rfc4492 "RFC 4492")
- `PSK` - [RFC 4279](https://tools.ietf.org/html/rfc4279 "RFC 4279")
- `DSS` - [FIPS186-4](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-4.pdf "FIPS186-4")
- `DH_anon` - [RFC 2631](https://tools.ietf.org/html/rfc2631 "RFC 2631")  - [RFC 7919](https://tools.ietf.org/html/rfc7919 "RFC 7919")
- `DHE_RSA` - [RFC 2631](https://tools.ietf.org/html/rfc2631 "RFC 2631")  - [RFC 7919](https://tools.ietf.org/html/rfc7919 "RFC 7919")
- `DHE_DSS` - [RFC 2631](https://tools.ietf.org/html/rfc2631 "RFC 2631")  - [RFC 7919](https://tools.ietf.org/html/rfc7919 "RFC 7919")
- `ECDHE_ECDSA` - [RFC 8422](https://tools.ietf.org/html/rfc8422 "RFC 8422")
- `ECDHE_PSK`  - [RFC 8422](https://tools.ietf.org/html/rfc8422 "RFC 8422")  - [RFC 5489](https://tools.ietf.org/html/rfc5489 "RFC 5489")
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
- `CHACHA20_POLY1305`  - [RFC 7905](https://tools.ietf.org/html/rfc7905 "RFC 7905")  - [RFC 7539](https://tools.ietf.org/html/rfc7539 "RFC 7539")

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

Finally, verify that the server or termination proxy at which the HTTPS connection terminates is configured according to best practices. See also the [OWASP Transport Layer Protection cheat sheet](https://github.com/OWASP/CheatSheetSeries/blob/master/cheatsheets/Transport_Layer_Protection_Cheat_Sheet.md "Transport Layer Protection Cheat Sheet") and the [Qualys SSL/TLS Deployment Best Practices](https://dev.ssllabs.com/projects/best-practices/ "Qualys SSL/TLS Deployment Best Practices").

## Intercepting HTTP(S) Traffic

In many cases, it is most practical to configure a system proxy on the mobile device, so that HTTP(S) traffic is redirected through an _interception proxy_ running on your host computer. By monitoring the requests between the mobile app client and the backend, you can easily map the available server-side APIs and gain insight into the communication protocol. Additionally, you can replay and manipulate requests to test for server-side vulnerabilities.

Several free and commercial proxy tools are available. Here are some of the most popular:

- [Burp Suite](0x08a-Testing-Tools.md#burp-suite)
- [OWASP ZAP](0x08a-Testing-Tools.md#owasp-zap)

To use the interception proxy, you'll need to run it on your host computer and configure the mobile app to route HTTP(S) requests to your proxy. In most cases, it is enough to set a system-wide proxy in the network settings of the mobile device - if the app uses standard HTTP APIs or popular libraries such as `okhttp`, it will automatically use the system settings.

<img src="Images/Chapters/0x04f/BURP.png" width="100%" />

Using a proxy breaks SSL certificate verification and the app will usually fail to initiate TLS connections. To work around this issue, you can install your proxy's CA certificate on the device. We'll explain how to do this in the OS-specific "Basic Security Testing" chapters.

## Intercepting Non-HTTP Traffic

Interception proxies such as [Burp](0x08a-Testing-Tools.md#burp-suite) and [OWASP ZAP](0x08a-Testing-Tools.md#owasp-zap) won't show non-HTTP traffic, because they aren't capable of decoding it properly by default. There are, however, Burp plugins available such as:

- [Burp-non-HTTP-Extension](https://github.com/summitt/Burp-Non-HTTP-Extension "Burp-non-HTTP-Extension") and
- [Mitm-relay](https://github.com/jrmdev/mitm_relay "Mitm-relay").

These plugins can visualize non-HTTP protocols and you will also be able to intercept and manipulate the traffic.

Note that this setup can sometimes become very tedious and is not as straightforward as testing HTTP.

## Intercepting Traffic from the App Process

Depending on your goal while testing the app, sometimes it is enough to monitor the traffic before it reaches the network layer or when the responses are received in the app.

You don't need to deploy a fully fledged MITM attack if you simply want to know if a certain piece of sensitive data is being transmitted to the network. In this case you wouldn't even have to bypass pinning, if implemented. You just have to hook the right functions, e.g. `SSL_write` and `SSL_read` from openssl.

This would work pretty well for apps using standard API libraries functions and classes, however there might be some downsides:

- the app might implement a custom network stack and you'll have to spend time analyzing the app to find out the APIs that you can use (see section "Searching for OpenSSL traces with signature analysis" in [this blog post](https://hackmag.com/security/ssl-sniffing/)).
- it might be very time consuming to craft the right hooking scripts to re-assemble HTTP response pairs (across many method calls and execution threads). You might find [ready-made scripts](https://github.com/fanxs-t/Android-SSL_read-write-Hook/blob/master/frida-hook.py) and even for [alternative network stacks](https://codeshare.frida.re/@owen800q/okhttp3-interceptor/) but depending on the app and the platform these scripts might need a lot of maintenance and might not _always work_.

See some examples:

- ["Universal interception. How to bypass SSL Pinning and monitor traffic of any application"](https://hackmag.com/security/ssl-sniffing/), sections "Grabbing payload prior to transmission" and "Grabbing payload prior to encryption"
- ["Frida as an Alternative to Network Tracing"](https://gaiaslastlaugh.medium.com/frida-as-an-alternative-to-network-tracing-5173cfbd7a0b)

> This technique is also useful for other types of traffic such as BLE, NFC, etc. where deploying a MITM attack might be very costly and or complex.

## Intercepting Traffic on the Network Layer

Dynamic analysis by using an interception proxy can be straight forward if standard libraries are used in the app and all communication is done via HTTP. But there are several cases where this is not working:

- If mobile application development platforms like [Xamarin](https://www.xamarin.com/platform "Xamarin") are used that ignore the system proxy settings;
- If mobile applications verify if the system proxy is used and refuse to send requests through a proxy;
- If you want to intercept push notifications, like for example GCM/FCM on Android;
- If XMPP or other non-HTTP protocols are used.

In these cases you need to monitor and analyze the network traffic first in order to decide what to do next. Luckily, there are several options for redirecting and intercepting network communication:

- Route the traffic through the host computer. You can set up host computer as the network gateway, e.g. by using the built-in Internet Sharing facilities of your operating system. You can then use [Wireshark](0x08a-Testing-Tools.md#wireshark) to sniff any traffic from the mobile device.
- Sometimes you need to execute a MITM attack to force the mobile device to talk to you. For this scenario you should consider [bettercap](0x08a-Testing-Tools.md#bettercap) or use your own access point to redirect network traffic from the mobile device to your host computer (see below).
- On a rooted device, you can use hooking or code injection to intercept network-related API calls (e.g. HTTP requests) and dump or even manipulate the arguments of these calls. This eliminates the need to inspect the actual network data. We'll talk in more detail about these techniques in the "Reverse Engineering and Tampering" chapters.
- On macOS, you can create a "Remote Virtual Interface" for sniffing all traffic on an iOS device. We'll describe this method in the chapter "Basic Security Testing on iOS".

### Simulating a Man-in-the-Middle Attack with bettercap

#### Network Setup

To be able to get a man-in-the-middle position your host computer should be in the same wireless network as the mobile phone and the gateway it communicates to. Once this is done you need the IP address of your mobile phone. For a full dynamic analysis of a mobile app, all network traffic should be intercepted.

#### MITM Attack

Start your preferred network analyzer tool first, then start [bettercap](0x08a-Testing-Tools.md#bettercap) with the following command and replace the IP address below (X.X.X.X) with the target you want to execute the MITM attack against.

```bash
$ sudo bettercap -eval "set arp.spoof.targets X.X.X.X; arp.spoof on; set arp.spoof.internal true; set arp.spoof.fullduplex true;"
bettercap v2.22 (built for darwin amd64 with go1.12.1) [type 'help' for a list of commands]

[19:21:39] [sys.log] [inf] arp.spoof enabling forwarding
[19:21:39] [sys.log] [inf] arp.spoof arp spoofer started, probing 1 targets.
```

bettercap will then automatically send the packets to the network gateway in the (wireless) network and you are able to sniff the traffic. Beginning of 2019 support for [full duplex ARP spoofing](https://github.com/bettercap/bettercap/issues/426 "Full Duplex ARP Spoofing") was added to bettercap.

On the mobile phone start the browser and navigate to `http://example.com`, you should see output like the following when you are using Wireshark.

<img src="Images/Chapters/0x04f/bettercap.png" width="100%" />

If that's the case, you are now able to see the complete network traffic that is sent and received by the mobile phone. This includes also DNS, DHCP and any other form of communication and can therefore be quite "noisy". You should therefore know how to use [DisplayFilters in Wireshark](https://wiki.wireshark.org/DisplayFilters "DisplayFilters") or know [how to filter in tcpdump](https://danielmiessler.com/study/tcpdump/#gs.OVQjKbk "A tcpdump Tutorial and Primer with Examples") to focus only on the relevant traffic for you.

> Man-in-the-middle attacks work against any device and operating system as the attack is executed on OSI Layer 2 through ARP Spoofing. When you are MITM you might not be able to see clear text data, as the data in transit might be encrypted by using TLS, but it will give you valuable information about the hosts involved, the protocols used and the ports the app is communicating with.

### Simulating a Man-in-the-Middle Attack with an access point

#### Network Setup

A simple way to simulate a man-in-the-middle (MITM) attack is to configure a network where all packets between the devices in scope and the target network are going through your host computer. In a mobile penetration test, this can be achieved by using an access point the mobile devices and your host computer are connected to. Your host computer is then becoming a router and an access point.

Following scenarios are possible:

- Use your host computer's built-in WiFi card as an access point and use your wired connection to connect to the target network.
- Use an external USB WiFi card as an access point and use your host computer's built-in WiFi to connect to the target network (can be vice-versa).
- Use a separate access point and redirect the traffic to your host computer.

The scenario with an external USB WiFi card require that the card has the capability to create an access point. Additionally, you need to install some tools and/or configure the network to enforce a man-in-the-middle position (see below). You can verify if your WiFi card has AP capabilities by using the command `iwconfig` on Kali Linux:

```bash
iw list | grep AP
```

The scenario with a separate access point requires access to the configuration of the AP and you should check first if the AP supports either:

- port forwarding or
- has a span or mirror port.

In both cases the AP needs to be configured to point to your host computer's IP. Your host computer must be connected to the AP (via wired connection or WiFi) and you need to have connection to the target network (can be the same connection as to the AP). Some additional configuration may be required on your host computer to route traffic to the target network.

> If the separate access point belongs to the customer, all changes and configurations should be clarified prior to the engagement and a backup should be created, before making any changes.

<img src="Images/Chapters/0x04f/architecture_MITM_AP.png" width="100%" />

#### Installation

The following procedure is setting up a man-in-the-middle position using an access point and an additional network interface:

Create a WiFi network either through a separate access point or through an external USB WiFi card or through the built-in card of your host computer.

This can be done by using the built-in utilities on macOS. You can use [share the internet connection on Mac with other network users](https://support.apple.com/en-ke/guide/mac-help/mchlp1540/mac "Share the internet connection on Mac with other network users").

For all major Linux and Unix operating systems you need tools such as:

- hostapd
- dnsmasq
- iptables
- wpa_supplicant
- airmon-ng

For Kali Linux you can install these tools with `apt-get`:

```bash
apt-get update
apt-get install hostapd dnsmasq aircrack-ng
```

> iptables and wpa_supplicant are installed by default on Kali Linux.

In case of a separate access point, route the traffic to your host computer. In case of an external USB WiFi card or built-in WiFi card the traffic is already available on your host computer.

Route the incoming traffic coming from the WiFi to the additional network interface where the traffic can reach the target network. Additional network interface can be wired connection or other WiFi card, depending on your setup.

#### Configuration

We focus on the configuration files for Kali Linux. Following values need to be defined:

- wlan1 - id of the AP network interface (with AP capabilities),
- wlan0 - id of the target network interface (this can be wired interface or other WiFi card)
- 10.0.0.0/24 - IP addresses and mask of AP network

The following configuration files need to be changed and adjusted accordingly:

- hostapd.conf

    ```bash
    # Name of the WiFi interface we use
    interface=wlan1
    # Use the nl80211 driver
    driver=nl80211
    hw_mode=g
    channel=6
    wmm_enabled=1
    macaddr_acl=0
    auth_algs=1
    ignore_broadcast_ssid=0
    wpa=2
    wpa_key_mgmt=WPA-PSK
    rsn_pairwise=CCMP
    # Name of the AP network
    ssid=STM-AP
    # Password of the AP network
    wpa_passphrase=password
    ```

- wpa_supplicant.conf

    ```bash
    network={
        ssid="NAME_OF_THE_TARGET_NETWORK"
        psk="PASSWORD_OF_THE_TARGET_NETWORK"
    }
    ```

- dnsmasq.conf

    ```bash
    interface=wlan1
    dhcp-range=10.0.0.10,10.0.0.250,12h
    dhcp-option=3,10.0.0.1
    dhcp-option=6,10.0.0.1
    server=8.8.8.8
    log-queries
    log-dhcp
    listen-address=127.0.0.1
    ```

#### MITM Attack

To be able to get a man-in-the-middle position you need to run the above configuration. This can be done by using the following commands on Kali Linux:

```bash
# check if other process is not using WiFi interfaces
$ airmon-ng check kill
# configure IP address of the AP network interface
$ ifconfig wlan1 10.0.0.1 up
# start access point
$ hostapd hostapd.conf
# connect the target network interface
$ wpa_supplicant -B -i wlan0 -c wpa_supplicant.conf
# run DNS server
$ dnsmasq -C dnsmasq.conf -d
# enable routing
$ echo 1 > /proc/sys/net/ipv4/ip_forward
# iptables will NAT connections from AP network interface to the target network interface
$ iptables --flush
$ iptables --table nat --append POSTROUTING --out-interface wlan0 -j MASQUERADE
$ iptables --append FORWARD --in-interface wlan1 -j ACCEPT
$ iptables -t nat -A POSTROUTING -j MASQUERADE
```

Now you can connect your mobile devices to the access point.

### Network Analyzer Tool

Install a tool that allows you to monitor and analyze the network traffic that will be redirected to your host computer. The two most common network monitoring (or capturing) tools are:

- [Wireshark](https://www.wireshark.org "Wireshark") (CLI pendant: [TShark](https://www.wireshark.org/docs/man-pages/tshark.html "TShark"))
- [tcpdump](https://www.tcpdump.org/tcpdump_man.html "tcpdump")

Wireshark offers a GUI and is more straightforward if you are not used to the command line. If you are looking for a command line tool you should either use TShark or tcpdump. All of these tools are available for all major Linux and Unix operating systems and should be part of their respective package installation mechanisms.

### Setting a Proxy Through Runtime Instrumentation

On a rooted or jailbroken device, you can also use runtime hooking to set a new proxy or redirect network traffic. This can be achieved with hooking tools like [Inspeckage](https://github.com/ac-pm/Inspeckage "Inspeckage") or code injection frameworks like [Frida](https://www.frida.re "Frida") and [cycript](http://www.cycript.org "cycript"). You'll find more information about runtime instrumentation in the "Reverse Engineering and Tampering" chapters of this guide.

### Example - Dealing with Xamarin

As an example, we will now redirect all requests from a Xamarin app to an interception proxy.

Xamarin is a mobile application development platform that is capable of producing [native Android](https://docs.microsoft.com/en-us/xamarin/android/get-started/ "Getting Started with Android") and [iOS apps](https://docs.microsoft.com/en-us/xamarin/ios/get-started/ "Getting Started with iOS") by using Visual Studio and C# as programming language.

When testing a Xamarin app and when you are trying to set the system proxy in the Wi-Fi settings you won't be able to see any HTTP requests in your interception proxy, as the apps created by Xamarin do not use the local proxy settings of your phone. There are three ways to resolve this:

- 1st way: Add a [default proxy to the app](https://developer.xamarin.com/api/type/System.Net.WebProxy/ "System.Net.WebProxy Class"), by adding the following code in the `OnCreate` or `Main` method and re-create the app:

    ```cs
    WebRequest.DefaultWebProxy = new WebProxy("192.168.11.1", 8080);
    ```

- 2nd way: Use bettercap in order to get a man-in-the-middle position (MITM), see the section above about how to setup a MITM attack. When being MITM you only need to redirect port 443 to your interception proxy running on localhost. This can be done by using the command `rdr` on macOS:

    ```bash
    $ echo "
    rdr pass inet proto tcp from any to any port 443 -> 127.0.0.1 port 8080
    " | sudo pfctl -ef -
    ```

    For Linux systems you can use `iptables`:

    ```bash
    sudo iptables -t nat -A PREROUTING -p tcp --dport 443 -j DNAT --to-destination 127.0.0.1:8080
    ```

    As last step, you need to set the option 'Support invisible proxy' in the listener settings of [Burp Suite](0x08a-Testing-Tools.md#burp-suite).

- 3rd way: Instead of bettercap an alternative is tweaking the `/etc/hosts` on the mobile phone. Add an entry into `/etc/hosts` for the target domain and point it to the IP address of your intercepting proxy. This creates a similar situation of being MITM as with bettercap and you need to redirect port 443 to the port which is used by your interception proxy. The redirection can be applied as mentioned above. Additionally, you need to redirect traffic from your interception proxy to the original location and port.

> When redirecting traffic you should create narrow rules to the domains and IPs in scope, to minimize noise and out-of-scope traffic.

The interception proxy need to listen to the port specified in the port forwarding rule above, which is 8080.

When a Xamarin app is configured to use a proxy (e.g. by using `WebRequest.DefaultWebProxy`) you need to specify where traffic should go next, after redirecting the traffic to your intercepting proxy. You need to redirect the traffic to the original location. The following procedure is setting up a redirection in [Burp](0x08a-Testing-Tools.md#burp-suite) to the original location:

1. Go to **Proxy** tab and click on **Options**
2. Select and edit your listener from the list of proxy listeners.
3. Go to **Request handling** tab and set:

    - Redirect to host: provide original traffic location.
    - Redirect to port: provide original port location.
    - Set 'Force use of SSL' (when HTTPS is used) and set 'Support invisible proxy'.

<img src="Images/Chapters/0x04f/burp_xamarin.png" width="100%" />

#### CA Certificates

If not already done, install the CA certificates in your mobile device which will allow us to intercept HTTPS requests:

- [Install the CA certificate of your interception proxy into your Android phone](https://support.portswigger.net/customer/portal/articles/1841102-installing-burp-s-ca-certificate-in-an-android-device "Installing Burp\'s CA Certificate in an Android Device")
    > Note that starting with Android 7.0 (API level 24) the OS no longer trusts a user supplied CA certificate unless specified in the app. Bypassing this security measure will be addressed in the "Basic Security Testing" chapters.
- [Install the CA certificate of your interception proxy into your iOS phone](https://support.portswigger.net/customer/portal/articles/1841108-configuring-an-ios-device-to-work-with-burp "Configuring an iOS Device to Work With Burp")

#### Intercepting Traffic

Start using the app and trigger its functions. You should see HTTP messages showing up in your interception proxy.

> When using bettercap you need to activate "Support invisible proxying" in Proxy Tab / Options / Edit Interface
