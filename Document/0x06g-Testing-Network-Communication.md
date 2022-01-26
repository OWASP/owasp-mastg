# iOS Network Communication

Almost every iOS app acts as a client to one or more remote services. As this network communication usually takes place over untrusted networks such as public Wi-Fi, classical network based-attacks become a potential issue.

Most modern mobile apps use variants of HTTP-based web services, as these protocols are well-documented and supported.

## Overview

### iOS App Transport Security

[App Transport Security (ATS)](https://developer.apple.com/library/content/documentation/General/Reference/InfoPlistKeyReference/Articles/CocoaKeys.html "Information Property List Key Reference: Cocoa Keys") is a set of security checks that the operating system enforces when making connections with [NSURLConnection](https://developer.apple.com/reference/foundation/nsurlconnection "API Reference NSURLConnection"), [NSURLSession](https://developer.apple.com/reference/foundation/urlsession "API Reference NSURLSession") and [CFURL](https://developer.apple.com/reference/corefoundation/cfurl-rd7 "API Reference CFURL") to public hostnames. ATS is enabled by default for applications build on iOS 9 and above.

ATS is enforced only when making connections to public hostnames. Therefore any connection made to an IP address, unqualified domain names or TLD of .local is not protected with ATS.

The following is a summarized list of [App Transport Security Requirements](https://developer.apple.com/library/content/documentation/General/Reference/InfoPlistKeyReference/Articles/CocoaKeys.html "Information Property List Key Reference: Cocoa Keys"):

- No HTTP connections are allowed
- The X.509 Certificate has a SHA256 fingerprint and must be signed with at least a 2048-bit RSA key or a 256-bit Elliptic-Curve Cryptography (ECC) key.
- Transport Layer Security (TLS) version must be 1.2 or above and must support Perfect Forward Secrecy (PFS) through Elliptic Curve Diffie-Hellman Ephemeral (ECDHE) key exchange and AES-128 or AES-256 symmetric ciphers.

The cipher suite must be one of the following:

- `TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384`
- `TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256`
- `TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384`
- `TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA`
- `TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256`
- `TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA`
- `TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384`
- `TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256`
- `TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384`
- `TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256`
- `TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA`

#### ATS Exceptions

ATS restrictions can be disabled by configuring exceptions in the Info.plist file under the `NSAppTransportSecurity` key. These exceptions can be applied to:

- allow insecure connections (HTTP),
- lower the minimum TLS version,
- disable PFS or
- allow connections to local domains.

ATS exceptions can be applied globally or per domain basis. The application can globally disable ATS, but opt in for individual domains. The following listing from Apple Developer documentation shows the structure of the [`NSAppTransportSecurity`](https://developer.apple.com/library/content/documentation/General/Reference/InfoPlistKeyReference/Articles/CocoaKeys.html#//apple_ref/doc/plist/info/NSAppTransportSecurity "API Reference NSAppTransportSecurity") dictionary.

```objectivec
NSAppTransportSecurity : Dictionary {
    NSAllowsArbitraryLoads : Boolean
    NSAllowsArbitraryLoadsForMedia : Boolean
    NSAllowsArbitraryLoadsInWebContent : Boolean
    NSAllowsLocalNetworking : Boolean
    NSExceptionDomains : Dictionary {
        <domain-name-string> : Dictionary {
            NSIncludesSubdomains : Boolean
            NSExceptionAllowsInsecureHTTPLoads : Boolean
            NSExceptionMinimumTLSVersion : String
            NSExceptionRequiresForwardSecrecy : Boolean   // Default value is YES
            NSRequiresCertificateTransparency : Boolean
        }
    }
}
```

Source: [Apple Developer Documentation](https://developer.apple.com/library/content/documentation/General/Reference/InfoPlistKeyReference/Articles/CocoaKeys.html "Information Property List Key Reference: Cocoa Keys").

The following table summarizes the global ATS exceptions. For more information about these exceptions, please refer to [table 2 in the official Apple developer documentation](https://developer.apple.com/library/content/documentation/General/Reference/InfoPlistKeyReference/Articles/CocoaKeys.html#//apple_ref/doc/uid/TP40009251-SW34 "App Transport Security dictionary primary keys").

|  Key | Description |
| --------------| ------------|
| `NSAllowsArbitraryLoads` | Disable ATS restrictions globally excepts for individual domains specified under `NSExceptionDomains` |
| `NSAllowsArbitraryLoadsInWebContent` | Disable ATS restrictions for all the connections made from web views |
| `NSAllowsLocalNetworking` | Allow connection to unqualified domain names and .local domains |
| `NSAllowsArbitraryLoadsForMedia` | Disable all ATS restrictions for media loaded through the AV Foundations framework |

The following table summarizes the per-domain ATS exceptions. For more information about these exceptions, please refer to [table 3 in the official Apple developer documentation](https://developer.apple.com/library/content/documentation/General/Reference/InfoPlistKeyReference/Articles/CocoaKeys.html#//apple_ref/doc/uid/TP40009251-SW44 "App Transport Security dictionary primary keys").

|  Key | Description |
| --------------| ------------|
| `NSIncludesSubdomains` | Indicates whether ATS exceptions should apply to subdomains of the named domain |
| `NSExceptionAllowsInsecureHTTPLoads` | Allows HTTP connections to the named domain, but does not affect TLS requirements |
| `NSExceptionMinimumTLSVersion` | Allows connections to servers with TLS versions less than 1.2 |
| `NSExceptionRequiresForwardSecrecy` | Disable perfect forward secrecy (PFS) |

Starting from January 1 2017, Apple App Store review requires justification if one of the following ATS exceptions are defined.

- `NSAllowsArbitraryLoads`
- `NSAllowsArbitraryLoadsForMedia`
- `NSAllowsArbitraryLoadsInWebContent`
- `NSExceptionAllowsInsecureHTTPLoads`
- `NSExceptionMinimumTLSVersion`

### iOS Network APIs

Since iOS 12.0 the [Network](https://developer.apple.com/documentation/network) framework and the [`URLSession`](https://developer.apple.com/documentation/foundation/urlsession) class provide methods to load network and URL requests asynchronously and synchronously. Older iOS versions can utilize the [Sockets API](https://developer.apple.com/library/archive/documentation/NetworkingInternet/Conceptual/NetworkingTopics/Articles/UsingSocketsandSocketStreams.html).

#### Network Framework

The `Network` framework was introduced at [The Apple Worldwide Developers Conference (WWDC)](https://developer.apple.com/videos/play/wwdc2018/715 "Introducing Network.framework: A modern alternative to Sockets") in 2018 and is a replacement to the Sockets API. This low-level networking framework provides classes to send and receive data with built in dynamic networking, security and performance support.

TLS 1.3 is enabled by default in the `Network` framework, if the argument `using: .tls` is used. It is the preferred option over the legacy [Secure Transport](https://developer.apple.com/documentation/security/secure_transport "API Reference Secure Transport") framework.

#### URLSession

`URLSession` was built upon the `Network` framework and utilizes the same transport services. The class also uses TLS 1.3 by default, if the endpoint is HTTPS.

**`URLSession` should be used for HTTP and HTTPS connections, instead of utilizing the `Network` framework directly.** The `URLSession` class natively supports both URL schemes and is optimized for such connections. It requires less boilerplate code, reducing the propensity for errors and ensuring secure connections by default. The `Network` framework should only be used when there are low-level and/or advanced networking requirements.

The official Apple documentation includes examples of using the `Network` framework to [implement netcat](https://developer.apple.com/documentation/network/implementing_netcat_with_network_framework "Implementing netcat with Network Framework") and `URLSession` to [fetch website data into memory](https://developer.apple.com/documentation/foundation/url_loading_system/fetching_website_data_into_memory "Fetching Website Data into Memory").

## Testing Data Encryption on the Network (MSTG-NETWORK-1)

First, you should identify all network requests in the source code and ensure that no plain HTTP URLs are used. Make sure that sensitive information is sent over secure channels by using [`URLSession`](https://developer.apple.com/documentation/foundation/urlsession) (which uses the standard [URL Loading System from iOS](https://developer.apple.com/documentation/foundation/url_loading_system)) or [`Network`](https://developer.apple.com/documentation/network) (for socket-level communication using TLS and access to TCP and UDP).

Next, you should ensure that the app is not allowing cleartext HTTP traffic. Since iOS 9.0 cleartext HTTP traffic is blocked by default (due to App Transport Security (ATS)) but there are multiple ways in which an application can still send it:

- Configuring ATS to enable cleartext traffic by setting the `NSAppTransportSecurity` attribute to `true` on [`NSAppTransportSecurity`](https://developer.apple.com/documentation/bundleresources/information_property_list/nsapptransportsecurity) in the app [`Info.plist`](https://developer.apple.com/documentation/bundleresources/information_property_list).
- Using low-level APIs (e.g. [`Network`](https://developer.apple.com/documentation/network)) or [`CFNetwork`](https://developer.apple.com/documentation/cfnetwork) to set up a custom HTTP connection.
- Using a cross-platform framework (e.g. Flutter, Xamarin, ...), as these typically have their own implementations for HTTP libraries.

All of the above cases must be carefully analyzed as a whole. For example, even if the app does not permit cleartext traffic in its Android Manifest or Network Security Configuration, it might actually still be sending HTTP traffic. That could be the case if it's using a low-level API (for which Network Security Configuration is ignored) or a badly configured cross-platform framework.

For more information refer to the article "Preventing Insecure Network Connections" in the [Apple Developer Documentation](https://developer.apple.com/documentation/security/preventing_insecure_network_connections).

### Static Analysis

#### Testing Network API Usage

Start by identifying the network APIs used by the app and see if it mainly uses high-level networking APIs.

> **Apple Recommendation: Prefer High-Level Frameworks in Your App**: ATS doesn’t apply to calls your app makes to lower-level networking interfaces like the Network framework or CFNetwork. In these cases, you take responsibility for ensuring the security of the connection. You can construct a secure connection this way, but mistakes are both easy to make and costly. It’s typically safest to rely on the URL Loading System instead.

If it uses low-level APIs such as [`Network`](https://developer.apple.com/documentation/network)) or [`CFNetwork`](https://developer.apple.com/documentation/cfnetwork) you should further investigate if they are being used securely. For apps using cross-platform frameworks (e.g. Flutter, Xamarin, ...) you should analyze if they're being configured and used securely according to the framework's best practices.

#### Testing Network API Usage

You should verify if the app allows cleartext traffic. If the source code is available, open then `Info.plist` file in the application bundle directory and look for any exceptions within the [`NSAppTransportSecurity`](https://developer.apple.com/documentation/bundleresources/information_property_list/nsapptransportsecurity) optional key.

The following listing is an example of an exception configured to disable ATS restrictions globally.

```xml
    <key>NSAppTransportSecurity</key>
    <dict>
        <key>NSAllowsArbitraryLoads</key>
        <true/>
    </dict>
```

If the source code is not available, then the `Info.plist` file should be either obtained from a jailbroken device or by extracting the application IPA file. Convert it to a human readable format if needed (e.g. `plutil -convert xml1 Info.plist`) as explained in the chapter "iOS Basic Security Testing", section "The Info.plist File".

> Note: ATS should be examined taking the application's context into consideration. The application may *have to* define ATS exceptions to fulfill its intended purpose. For example, the Firefox iOS application has ATS disabled globally. This exception is acceptable because otherwise the application would not be able to connect to any HTTP website that does not have all the ATS requirements. ATS should include a [justification string](https://developer.apple.com/documentation/security/preventing_insecure_network_connections#3138036) for this (e.g. "The app must connect to a server managed by another entity that doesn’t support secure connections.").

#### Testing Network Security Exceptions

You should verify if the app has any network security exceptions configured by opening then `Info.plist` file in the application bundle directory and inspecting the [`NSAppTransportSecurity`](https://developer.apple.com/documentation/bundleresources/information_property_list/nsapptransportsecurity) optional key. Verify if it contains any exceptions and [inspect the corresponding justifications](https://developer.apple.com/documentation/security/preventing_insecure_network_connections#3138036) to discard that it might be part of the app intended purpose.

> **Apple Recommendation: Configure Exceptions Only When Needed; Prefer Server Fixes**: It’s always better to fix the server when faced with an ATS failure. Exceptions reduce the security of your app. Some also require justification when submitting an app to the App Store, as described in the next section.

Consider the following when inspecting ATS:

- ATS should be configured according to best practices by Apple and only be deactivated under certain circumstances.
- If the application connects to a defined number of domains that the application owner controls, then configure the servers to support the ATS requirements and opt-in for the ATS requirements within the app. In the following example, `example.com` is owned by the application owner and ATS is enabled for that domain using the [`NSExceptionDomains`](https://developer.apple.com/documentation/bundleresources/information_property_list/nsapptransportsecurity/nsexceptiondomains) sub-dictionary.

```xml
<key>NSAppTransportSecurity</key>
<dict>
    <key>NSAllowsArbitraryLoads</key>
    <true/>
    <key>NSExceptionDomains</key>
    <dict>
        <key>example.com</key>
        <dict>
            <key>NSIncludesSubdomains</key>
            <true/>
            <key>NSExceptionMinimumTLSVersion</key>
            <string>TLSv1.2</string>
            <key>NSExceptionAllowsInsecureHTTPLoads</key>
            <false/>
            <key>NSExceptionRequiresForwardSecrecy</key>
            <true/>
        </dict>
    </dict>
</dict>
```

- If connections to 3rd party domains are made (that are not under control of the app owner) it should be evaluated what ATS settings are not supported by the 3rd party domain and if they can be deactivated.
- If the application opens third party web sites in web views, then from iOS 10 onwards `NSAllowsArbitraryLoadsInWebContent` can be used to disable ATS restrictions for the content loaded in web views.
- If the application only needs to limit ATS exceptions to a single domain e.g. to access the insecure server http://example.com, it can set `NSExceptionAllowsInsecureHTTPLoads` to YES in order to maintain all the benefits of ATS for all other domains.

It is possible to verify which ATS settings can be used when communicating to a certain endpoint. On macOS the command line utility `nscurl` can be used. A permutation of different settings will be executed and verified against the specified endpoint. If the default ATS secure connection test is passing, ATS can be used in its default secure configuration. If there are any fails in the nscurl output, please change the server side configuration of TLS to make the serverside more secure, rather than weakening the configuration in ATS on the client. See the article "Identifying the Source of Blocked Connections" in the [Apple Developer Documentation](https://developer.apple.com/documentation/security/preventing_insecure_network_connections/identifying_the_source_of_blocked_connections) for more details.

For more information on ATS exceptions please consult section "Configure Exceptions Only When Needed; Prefer Server Fixes" from the article "Preventing Insecure Network Connections" in the [Apple Developer Documentation](https://developer.apple.com/documentation/security/preventing_insecure_network_connections#3138482) and the [blog post by NowSecure on ATS](https://www.nowsecure.com/blog/2017/08/31/security-analysts-guide-nsapptransportsecurity-nsallowsarbitraryloads-app-transport-security-ats-exceptions/ "A guide to ATS").

### Dynamic Analysis

Intercept the tested app's incoming and outgoing network traffic and make sure that this traffic is encrypted. You can intercept network traffic in any of the following ways:

- Capture all HTTP(S) and Websocket traffic with an interception proxy like [OWASP ZAP](0x08-Testing-Tools.md#owasp-zap) or [Burp Suite](0x08-Testing-Tools.md#burp-suite) and make sure all requests are made via HTTPS instead of HTTP.
- Interception proxies like Burp and OWASP ZAP will show HTTP(S) traffic only. You can, however, use a Burp plugin such as [Burp-non-HTTP-Extension](https://github.com/summitt/Burp-Non-HTTP-Extension "Burp-non-HTTP-Extension") or the tool [mitm-relay](https://github.com/jrmdev/mitm_relay "mitm-relay") to decode and visualize communication via XMPP and other protocols.

> Some applications may not work with proxies like Burp and OWASP ZAP because of Certificate Pinning. In such a scenario, please check ["Testing Custom Certificate Stores and Certificate Pinning"](#testing-custom-certificate-stores-and-certificate-pinning-mstg-network-3-and-mstg-network-4).

For more details refer to:

- "Intercepting Traffic on the Network Layer" from chapter ["Testing Network Communication"](0x04f-Testing-Network-Communication.md#intercepting-traffic-on-the-network-layer)
- "Setting up a Network Testing Environment" from chapter [iOS Basic Security Testing](0x06b-Basic-Security-Testing.md#setting-up-a-network-testing-environment)

## Testing the TLS Settings (MSTG-NETWORK-2)

Refer to section "Verifying the TLS Settings" in chapter [Testing Network Communication](0x04f-Testing-Network-Communication.md#verifying-the-tls-settings-mstg-network-2) for details.

## Testing Custom Certificate Stores and Certificate Pinning (MSTG-NETWORK-3 and MSTG-NETWORK-4)

### Overview

Certificate Authorities are an integral part of a secure client server communication and they are predefined in the trust store of each operating system. On iOS you are automatically trusting an enormous amount of certificates which you can look up in detail in the Apple documentation, that will show you [lists of available trusted root certificates for each iOS version](https://support.apple.com/en-gb/HT204132 "Lists of available trusted root certificates in iOS").

CAs can be added to the trust store, either manually through the user, by an MDM that manages your enterprise device or through malware. The question is then can I trust all of those CAs and should my app rely on the trust store?

In order to address this risk you can use certificate pinning. Certificate pinning is the process of associating the mobile app with a particular X.509 certificate of a server, instead of accepting any certificate signed by a trusted certificate authority. A mobile app that stores the server certificate or public key will subsequently only establish connections to the known server, thereby "pinning" the server. By removing trust in external certificate authorities (CAs), the attack surface is reduced. After all, there are many known cases where certificate authorities have been compromised or tricked into issuing certificates to impostors. A detailed timeline of CA breaches and failures can be found at [sslmate.com](https://sslmate.com/certspotter/failures "Timeline of PKI Security Failures").

The certificate can be pinned during development, or at the time the app first connects to the backend.
In that case, the certificate associated or 'pinned' to the host at when it seen for the first time. This second variant is slightly less secure, as an attacker intercepting the initial connection could inject their own certificate.

#### When the Pin Fails

Pinning failures can occur for various reasons: either the app is expecting another key or certificate than offered by the server, or there might be a man-in-the-middle attack occuring. In both cases and similar as with Android, there are various ways to respond to such a situation. Please see the section "[When the Pin Fails](0x05g-Testing-Network-Communication.md#when-the-pin-fails)" in the chapter "Android Network Communication".

### Static Analysis

Verify that the server certificate is pinned. Pinning can be implemented on various levels in terms of the certificate tree presented by the server:

1. Including server's certificate in the application bundle and performing verification on each connection. This requires an update mechanisms whenever the certificate on the server is updated.
2. Limiting certificate issuer to e.g. one entity and bundling the intermediate CA's public key into the application. In this way we limit the attack surface and have a valid certificate.
3. Owning and managing your own PKI. The application would contain the intermediate CA's public key. This avoids updating the application every time you change the certificate on the server, due to e.g. expiration. Note that using your own CA would cause the certificate to be self-singed.

The latest approach recommended by Apple is to specify a pinned CA public key in the `Info.plist` file under App Transport Security Settings. You can find an example in their article [Identity Pinning: How to configure server certificates for your app](https://developer.apple.com/news/?id=g9ejcf8y "Identity Pinning: How to configure server certificates for your app").

Another common approach is to use the [`connection:willSendRequest ForAuthenticationChallenge:`](https://developer.apple.com/documentation/foundation/nsurlconnectiondelegate/1414078-connection?language=objc "connection:willSendRequestForAuthenticationChallenge:") method of `NSURLConnectionDelegate` to check if the certificate provided by the server is valid and matches the certificate stored in the app. You can find more details in the [HTTPS Server Trust Evaluation](https://developer.apple.com/library/archive/technotes/tn2232/_index.html#//apple_ref/doc/uid/DTS40012884-CH1-SECNSURLCONNECTION "HTTPS Server Trust Evaluation") technical note.

Note that if you compare local and remote certificates, you will have to update the app when the remote certificate changes. A fallback certificate can be stored in the app to make the transition smoother. Alternatively, the pin can be based on public-key comparison. Thus if the remote certificate changes, the public key stays the same.

The following third-party libraries include pinning functionality:

- [TrustKit](https://github.com/datatheorem/TrustKit "TrustKit"): here you can pin by setting the public key hashes in your Info.plist or provide the hashes in a dictionary. See their readme for more details.
- [AlamoFire](https://github.com/Alamofire/Alamofire "AlamoFire"): here you can define a `ServerTrustPolicy` per domain for which you can define the pinning method.
- [AFNetworking](https://github.com/AFNetworking/AFNetworking "AfNetworking"): here you can set an `AFSecurityPolicy` to configure your pinning.

### Dynamic Analysis

#### Server certificate validation

Our test approach is to gradually relax security of the SSL handshake negotiation and check which security mechanisms are enabled.

1. Having Burp set up as a proxy, make sure that there is no certificate added to the trust store (**Settings** -> **General** -> **Profiles**) and that tools like SSL Kill Switch are deactivated. Launch your application and check if you can see the traffic in Burp. Any failures will be reported under 'Alerts' tab. If you can see the traffic, it means that there is no certificate validation performed at all. If however, you can't see any traffic and you have an information about SSL handshake failure, follow the next point.
2. Now, install the Burp certificate, as explained in [Burp's user documentation](https://support.portswigger.net/customer/portal/articles/1841109-installing-burp-s-ca-certificate-in-an-ios-device "Installing Burp\'s CA Certificate in an iOS Device"). If the handshake is successful and you can see the traffic in Burp, it means that the certificate is validated against the device's trust store, but no pinning is performed.
3. If executing the instructions from the previous step doesn't lead to traffic being proxied through burp, it may mean that the certificate is actually pinned and all security measures are in place. However, you still need to bypass the pinning in order to test the application. Please refer to the section "[Bypassing Certificate Pinning](#bypassing-certificate-pinning "Bypassing Certificate Pinning")" below for more information on this.

#### Client certificate validation

Some applications use two-way SSL handshake, meaning that application verifies server's certificate and server verifies client's certificate. You can notice this if there is an error in Burp 'Alerts' tab indicating that client failed to negotiate connection.

There is a couple of things worth noting:

1. The client certificate contains a private key that will be used for the key exchange.
2. Usually the certificate would also need a password to use (decrypt) it.
3. The certificate can be stored in the binary itself, data directory or in the Keychain.

The most common and improper way of doing two-way handshake is to store the client certificate within the application bundle and hardcode the password. This obviously does not bring much security, because all clients will share the same certificate.

Second way of storing the certificate (and possibly password) is to use the Keychain. Upon first login, the application should download the personal certificate and store it securely in the Keychain.

Sometimes applications have one certificate that is hardcoded and use it for the first login and then the personal certificate is downloaded. In this case, check if it's possible to still use the 'generic' certificate to connect to the server.

Once you have extracted the certificate from the application (e.g. using Cycript or Frida), add it as client certificate in Burp, and you will be able to intercept the traffic.

#### Bypassing Certificate Pinning

There are various ways to bypass SSL Pinning and the following section will describe it for jailbroken and non-jailbroken devices.

If you have a jailbroken device you can try one of the following tools that can automatically disable SSL Pinning:

- "[SSL Kill Switch 2](https://github.com/nabla-c0d3/ssl-kill-switch2 "SSL Kill Switch 2")" is one way to disable certificate pinning. It can be installed via the [Cydia](0x08-Testing-Tools.md#cydia) store. It will hook on to all high-level API calls and bypass certificate pinning.
- The [Burp Suite Mobile Assistant](0x08-Testing-Tools.md#burp-suite-mobile-assistant) app can also be used to bypass certificate pinning.

In some cases, certificate pinning is tricky to bypass. Look for the following when you can access the source code and recompile the app:

- the API calls `NSURLSession`, `CFStream`, and `AFNetworking`
- methods/strings containing words like "pinning", "X.509", "Certificate", etc.

If you don't have access to the source, you can try binary patching:

- If OpenSSL certificate pinning is used, you can try [binary patching](https://www.nccgroup.trust/us/about-us/newsroom-and-events/blog/2015/january/bypassing-openssl-certificate-pinning-in-ios-apps/ "Bypassing OpenSSL Certificate Pinning in iOS Apps").
- Sometimes, the certificate is a file in the application bundle. Replacing the certificate with Burp's certificate may be sufficient, but beware of the certificate's SHA sum. If it's hardcoded into the binary, you must replace it too!

It is also possible to bypass SSL Pinning on non-jailbroken devices by using Frida and Objection (this also works on jailbroken devices). After repackaging your application with Objection as described in "iOS Basic Security Testing", you can use the following command in Objection to disable common SSL Pinning implementations:

```bash
$ ios sslpinning disable
```

You can look into the [pinning.ts](https://github.com/sensepost/objection/blob/master/agent/src/ios/pinning.ts "pinning.ts") file to understand how the bypass works.

See also [Objection's documentation on Disabling SSL Pinning for iOS](https://github.com/sensepost/objection#ssl-pinning-bypass-running-for-an-ios-application "Disable SSL Pinning in iOS" ) for further information.

However, technologies and systems change over time, and this bypass technique might not work eventually. Hence, it's part of the tester work to do some research, since not every tool is able to keep up with OS versions quickly enough.

For instance, at the time of this writing objection bypass is not working for iOS 10 and above. However, looking in repositories like Frida CodeShare it's possible to find scripts to bypass specific versions, such as ["ios10-ssl-bypass"](https://codeshare.frida.re/@dki/ios10-ssl-bypass/) by @dki which actually works for iOS 10 and 11.

Some apps might implement custom SSL pinning methods, so the tester could also develop new bypass scripts making use of [Frida](https://github.com/OWASP/owasp-mstg/blob/master/Document/0x06b-Basic-Security-Testing.md#frida) and the techniques explained in the ["iOS Reverse Engineering"](https://github.com/OWASP/owasp-mstg/blob/master/Document/0x06c-Reverse-Engineering-and-Tampering.md) chapter.

If you want to get more details about white box testing and typical code patterns, refer to [#thiel]. It contains descriptions and code snippets illustrating the most common certificate pinning techniques.

## References

- [#thiel] - David Thiel. iOS Application Security, No Starch Press, 2015

### OWASP MASVS

- MSTG-NETWORK-2: "The TLS settings are in line with current best practices, or as close as possible if the mobile operating system does not support the recommended standards."
- MSTG-NETWORK-3: "The app verifies the X.509 certificate of the remote endpoint when the secure channel is established. Only certificates signed by a trusted CA are accepted."
- MSTG-NETWORK-4: "The app either uses its own certificate store, or pins the endpoint certificate or public key, and subsequently does not establish connections with endpoints that offer a different certificate or key, even if signed by a trusted CA."

### Nscurl

- A guide to ATS - Blog post by NowSecure - <https://www.nowsecure.com/blog/2017/08/31/security-analysts-guide-nsapptransportsecurity-nsallowsarbitraryloads-app-transport-security-ats-exceptions/>
