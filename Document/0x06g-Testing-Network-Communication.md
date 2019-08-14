## iOS Network APIs

Almost every iOS app acts as a client to one or more remote services. As this network communication usually takes place over untrusted networks such as public Wi-Fi, classical network based-attacks become a potential issue.

Most modern mobile apps use variants of HTTP based web-services, as these protocols are well-documented and supported. On iOS, the `NSURLConnection` class provides methods to load URL requests asynchronously and synchronously.

### App Transport Security (MSTG-NETWORK-2)

#### Overview

[App Transport Security (ATS)](https://developer.apple.com/library/content/documentation/General/Reference/InfoPlistKeyReference/Articles/CocoaKeys.html "Information Property List Key Reference: Cocoa Keys") is a set of security checks that the operating system enforces when making connections with [NSURLConnection](https://developer.apple.com/reference/foundation/nsurlconnection "API Reference NSURLConnection"), [NSURLSession](https://developer.apple.com/reference/foundation/urlsession "API Reference NSURLSession") and [CFURL](https://developer.apple.com/reference/corefoundation/cfurl-rd7 "API Reference CFURL") to public hostnames. ATS is enabled by default for applications build on iOS SDK 9 and above.

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

##### ATS Exceptions

ATS restrictions can be disabled by configuring exceptions in the Info.plist file under the `NSAppTransportSecurity` key. These exceptions can be applied to:

- allow insecure connections (HTTP),
- lower the minimum TLS version,
- disable PFS or
- allow connections to local domains.

ATS exceptions can be applied globally or per domain basis. The application can globally disable ATS, but opt in for individual domains. The following listing from Apple Developer documentation shows the structure of the `[NSAppTransportSecurity](https://developer.apple.com/library/content/documentation/General/Reference/InfoPlistKeyReference/Articles/CocoaKeys.html#//apple_ref/doc/plist/info/NSAppTransportSecurity "API Reference NSAppTransportSecurity")` dictionary.

```objc
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
| -----| ------------|
| `NSAllowsArbitraryLoads` | Disable ATS restrictions globally excepts for individual domains specified under `NSExceptionDomains` |
| `NSAllowsArbitraryLoadsInWebContent` | Disable ATS restrictions for all the connections made from web views |
| `NSAllowsLocalNetworking` | Allow connection to unqualified domain names and .local domains |
| `NSAllowsArbitraryLoadsForMedia` | Disable all ATS restrictions for media loaded through the AV Foundations framework |

The following table summarizes the per-domain ATS exceptions. For more information about these exceptions, please refer to [table 3 in the official Apple developer documentation](https://developer.apple.com/library/content/documentation/General/Reference/InfoPlistKeyReference/Articles/CocoaKeys.html#//apple_ref/doc/uid/TP40009251-SW44 "App Transport Security dictionary primary keys").

|  Key | Description |
| -----| ------------|
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

However this decline is extended later by Apple stating [“To give you additional time to prepare, this deadline has been extended and we will provide another update when a new deadline is confirmed”](https://developer.apple.com/news/?id=12212016b "Apple Developer Portal Announcement - Supporting App Transport Security")

#### Analyzing the ATS Configuration

If the source code is available, open then `Info.plist` file in the application bundle directory and look for any exceptions that the application developer has configured. This file should be examined taking the applications context into consideration.

The following listing is an example of an exception configured to disable ATS restrictions globally.

```xml
    <key>NSAppTransportSecurity</key>
    <dict>
        <key>NSAllowsArbitraryLoads</key>
        <true/>
    </dict>
```

If the source code is not available, then the `Info.plist` file should be either obtained from a jailbroken device or by extracting the application IPA file. Convert it to a human readable format if needed (e.g. `plutil -convert xml1 Info.plist`) as explained in the chapter "iOS Basic Security Testing", section "The Info.plist File".

The application may have ATS exceptions defined to allow it’s normal functionality. For an example, the Firefox iOS application has ATS disabled globally. This exception is acceptable because otherwise the application would not be able to connect to any HTTP website that does not have all the ATS requirements.

#### Recommendations for usage of ATS

It is possible to verify which ATS settings can be used when communicating to a certain endpoint. On macOS the command line utility `nscurl` is available to check the same. The command can be used as follows:

```shell
/usr/bin/nscurl --ats-diagnostics https://www.example.com
Starting ATS Diagnostics

Configuring ATS Info.plist keys and displaying the result of HTTPS loads to https://www.example.com.
A test will "PASS" if URLSession:task:didCompleteWithError: returns a nil error.
Use '--verbose' to view the ATS dictionaries used and to display the error received in URLSession:task:didCompleteWithError:.
================================================================================

Default ATS Secure Connection
---
ATS Default Connection
Result : PASS
---

================================================================================

Allowing Arbitrary Loads

---
Allow All Loads
Result : PASS
---

================================================================================

Configuring TLS exceptions for www.example.com

---
TLSv1.3
2019-01-15 09:39:27.892 nscurl[11459:5126999] NSURLSession/NSURLConnection HTTP load failed (kCFStreamErrorDomainSSL, -9800)
Result : FAIL
---
```

The output above only shows the first few results of nscurl. A permutation of different settings is executed and verified against the specified endpoint. If the default ATS secure connection test is passing, ATS can be used in it's default secure configuration.

> If there are any fails in the nscurl output, please change the server side configuration of TLS to make the serverside more secure, instead of weakening the configuration in ATS on the client.

For more information on this topic please consult the [blog post by NowSecure on ATS](https://www.nowsecure.com/blog/2017/08/31/security-analysts-guide-nsapptransportsecurity-nsallowsarbitraryloads-app-transport-security-ats-exceptions/ "A guide to ATS").

In general it can be summarized:

- ATS should be configured according to best practices by Apple and only be deactivated under certain circumstances.
- If the application connects to a defined number of domains that the application owner controls, then configure the servers to support the ATS requirements and opt-in for the ATS requirements within the app. In the following example, `example.com` is owned by the application owner and ATS is enabled for that domain.

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
- If the application opens third party web sites in web views, then from iOS 10 onwards `NSAllowsArbitraryLoadsInWebContent` can be used to disable ATS restrictions for the content loaded in web views

### Testing Custom Certificate Stores and Certificate Pinning (MSTG-NETWORK-3 and MSTG-NETWORK-4)

#### Overview

Certificate Authorities are an integral part of a secure client server communication and they are predefined in the trust store of each operating system. On iOS you are automatically trusting an enormous amount of certificates which you can look up in detail in the Apple documentation, that will show you [lists of available trusted root certificates for each iOS version](https://support.apple.com/en-gb/HT204132 "Lists of available trusted root certificates in iOS").

CAs can be added to the trust store, either manually through the user, by an MDM that manages your enterprise device or through malware. The question is then can I trust all of those CAs and should my app rely on the trust store?

In order to address this risk you can use certificate pinning. Certificate pinning is the process of associating the mobile app with a particular X.509 certificate of a server, instead of accepting any certificate signed by a trusted certificate authority. A mobile app that stores the server certificate or public key will subsequently only establish connections to the known server, thereby "pinning" the server. By removing trust in external certificate authorities (CAs), the attack surface is reduced. After all, there are many known cases where certificate authorities have been compromised or tricked into issuing certificates to impostors. A detailed timeline of CA breaches and failures can be found at [sslmate.com](https://sslmate.com/certspotter/failures "Timeline of PKI Security Failures").

The certificate can be pinned during development, or at the time the app first connects to the backend.
In that case, the certificate associated or 'pinned' to the host at when it seen for the first time. This second variant is slightly less secure, as an attacker intercepting the initial connection could inject their own certificate.

Note that there are various ways to work with a failing pin:

- Inform the user about not being able to connect to the backend and stop all operations. The app can check whether there is an update and inform the user about updating to the latest version of the app if available. 
  - Additionally a call can be made to the backend or to a crash-reporting service that the pinning has failed to inform the developer and/or backend of the attack or misconfiguration.
- Only inform the backend by doing a call with slightly different parameters, which automatically informs the backend that pinning failed. From here on, only a limited amounts of APIs should be available which do not involve processing information that has a higher risk rating.

Which option you choose depends on how important availability is compared to the complexity of maintaining the application. In all cases, the backend or crash-reporting service should be informed in order to make sure that the app can be fixed in case of a misconfiguration.

#### Static Analysis

Verify that the server certificate is pinned. Pinning can be implemented on various levels in terms of the certificate tree presented by the server:

1. Including server's certificate in the application bundle and performing verification on each connection. This requires an update mechanisms whenever the certificate on the server is updated.
2. Limiting certificate issuer to e.g. one entity and bundling the intermediate CA's public key into the application. In this way we limit the attack surface and have a valid certificate.
3. Owning and managing your own PKI. The application would contain the intermediate CA's public key. This avoids updating the application every time you change the certificate on the server, due to e.g. expiration. Note that using your own CA would cause the certificate to be self-singed.

The code presented below shows how it is possible to check if the certificate provided by the server matches the certificate stored in the app. The method below implements the connection authentication and tells the delegate that the connection will send a request for an authentication challenge.

The delegate must implement `connection:canAuthenticateAgainstProtectionSpace:` and `connection: forAuthenticationChallenge`. Within `connection: forAuthenticationChallenge`, the delegate must call `SecTrustEvaluate` to perform customary X.509 checks. The snippet below implements a check of the certificate.

```objc

(void)connection:(NSURLConnection *)connection willSendRequestForAuthenticationChallenge:(NSURLAuthenticationChallenge *)challenge
{
  SecTrustRef serverTrust = challenge.protectionSpace.serverTrust;
  SecCertificateRef certificate = SecTrustGetCertificateAtIndex(serverTrust, 0);
  NSData *remoteCertificateData = CFBridgingRelease(SecCertificateCopyData(certificate));
  NSString *cerPath = [[NSBundle mainBundle] pathForResource:@"MyLocalCertificate" ofType:@"cer"];
  NSData *localCertData = [NSData dataWithContentsOfFile:cerPath];
  The control below can verify if the certificate received by the server is matching the one pinned in the client.
  if ([remoteCertificateData isEqualToData:localCertData]) {
  NSURLCredential *credential = [NSURLCredential credentialForTrust:serverTrust];
  [[challenge sender] useCredential:credential forAuthenticationChallenge:challenge];
}
else {
  [[challenge sender] cancelAuthenticationChallenge:challenge];
}
```

Note that the certificate pinning example above has a major drawback when you use certificate pinning and the certificate changes, then the pin is invalidated. If you can reuse the public key of the server, then you can create a new certificate with that same public key, which will ease the maintenance. There are various ways in which you can do this:

- Implement your own pin based on the public key: Change the comparison `if ([remoteCertificateData isEqualToData:localCertData]) {` in our example to a comparison of the key-bytes or the certificate-thumb.
- Use [TrustKit](https://github.com/datatheorem/TrustKit "TrustKit"): here you can pin by setting the public key hashes in your Info.plist or provide the hashes in a dictionary. See their readme for more details.
- Use [AlamoFire](https://github.com/Alamofire/Alamofire "AlamoFire"): here you can define a `ServerTrustPolicy` per domain for which you can define the pinning method.
- Use [AFNetworking](https://github.com/AFNetworking/AFNetworking "AfNetworking"): here you can set an `AFSecurityPolicy` to configure your pinning.

#### Dynamic Analysis

##### Server certificate validation

Our test approach is to gradually relax security of the SSL handshake negotiation and check which security mechanisms are enabled.

1. Having Burp set up as a proxy, make sure that there is no certificate added to the trust store (Settings -> General -> Profiles) and that tools like SSL Kill Switch are deactivated. Launch your application and check if you can see the traffic in Burp. Any failures will be reported under 'Alerts' tab. If you can see the traffic, it means that there is no certificate validation performed at all. If however, you can't see any traffic and you have an information about SSL handshake failure, follow the next point.
2. Now, install the Burp certificate, as explained in [Burp's user documentation](https://support.portswigger.net/customer/portal/articles/1841109-installing-burp-s-ca-certificate-in-an-ios-device "Installing Burp's CA Certificate in an iOS Device"). If the handshake is successful and you can see the traffic in Burp, it means that the certificate is validated against the device's trust store, but no pinning is performed.
3. If executing the instructions from the previous step doesn't lead to traffic being proxied through burp, it may mean that the certificate is actually pinned and all security measures are in place. However, you still need to bypass the pinning in order to test the application. Please refer to the section "[Bypassing Certificate Pinning](#bypassing-certificate-pinning "Bypassing Certificate Pinning")" below for more information on this.

##### Client certificate validation

Some applications use two-way SSL handshake, meaning that application verifies server's certificate and server verifies client's certificate. You can notice this if there is an error in Burp 'Alerts' tab indicating that client failed to negotiate connection.

There is a couple of things worth noting:

1. The client certificate contains a private key that will be used for the key exchange.
2. Usually the certificate would also need a password to use (decrypt) it.
3. The certificate can be stored in the binary itself, data directory or in the Keychain.

The most common and improper way of doing two-way handshake is to store the client certificate within the application bundle and hardcode the password. This obviously does not bring much security, because all clients will share the same certificate.

Second way of storing the certificate (and possibly password) is to use the Keychain. Upon first login, the application should download the personal certificate and store it securely in the Keychain.

Sometimes applications have one certificate that is hardcoded and use it for the first login and then the personal certificate is downloaded. In this case, check if it's possible to still use the 'generic' certificate to connect to the server.

Once you have extracted the certificate from the application (e.g. using Cycript or Frida), add it as client certificate in Burp, and you will be able to intercept the traffic.

##### Bypassing Certificate Pinning

There are various ways to bypass SSL Pinning and the following section will describe it for jailbroken and non-jailbroken devices.

If you have a jailbroken device you can try one of the following tools that can automatically disable SSL Pinning:

- "[SSL Kill Switch 2](https://github.com/nabla-c0d3/ssl-kill-switch2 "SSL Kill Switch 2")" is one way to disable certificate pinning. It can be installed via the Cydia store. It will hook on to all high-level API calls and bypass certificate pinning.
- The Burp Suite app "[Mobile Assistant](https://portswigger.net/burp/help/mobile_testing_using_mobile_assistant.html "Using Burp Suite Mobile Assistant")" can also be used to bypass certificate pinning.

In some cases, certificate pinning is tricky to bypass. Look for the following when you can access the source code and recompile the app:

- the API calls `NSURLSession`, `CFStream`, and `AFNetworking`
- methods/strings containing words like "pinning", "X.509", "Certificate", etc.

If you don't have access to the source, you can try binary patching:

- If OpenSSL certificate pinning is used, you can try [binary patching](https://www.nccgroup.trust/us/about-us/newsroom-and-events/blog/2015/january/bypassing-openssl-certificate-pinning-in-ios-apps/ "Bypassing OpenSSL Certificate Pinning in iOS Apps").
- Sometimes, the certificate is a file in the application bundle. Replacing the certificate with Burp's certificate may be sufficient, but beware of the certificate's SHA sum. If it's hardcoded into the binary, you must replace it too!

It is also possible to bypass SSL Pinning on non-jailbroken devices by using Frida and Objection (this also works on jailbroken devices). After repackaging your application with Objection as described in "iOS Basic Security Testing", you can use the following command in Objection to disable common SSL Pinning implementations:

```shell
$ ios sslpinning disable
```

You can look into the [pinning.ts](https://github.com/sensepost/objection/blob/master/agent/src/ios/pinning.ts "pinning.ts") file to understand how the bypass works.

See also [Objection's documentation on Disabling SSL Pinning for iOS](https://github.com/sensepost/objection#ssl-pinning-bypass-running-for-an-ios-application "Disable SSL Pinning in iOS" ) for further information.

If you want to get more details about white box testing and typical code patterns, refer to [#thiel]. It contains descriptions and code snippets illustrating the most common certificate pinning techniques.

#### References

- [#thiel] - David Thiel. iOS Application Security, No Starch Press, 2015

##### OWASP Mobile Top 10 2016

- M3 - Insecure Communication - <https://www.owasp.org/index.php/Mobile_Top_10_2016-M3-Insecure_Communication>

##### OWASP MASVS

- MSTG-NETWORK-2: "The TLS settings are in line with current best practices, or as close as possible if the mobile operating system does not support the recommended standards."
- MSTG-NETWORK-3: "The app verifies the X.509 certificate of the remote endpoint when the secure channel is established. Only certificates signed by a trusted CA are accepted."
- MSTG-NETWORK-4: "The app either uses its own certificate store, or pins the endpoint certificate or public key, and subsequently does not establish connections with endpoints that offer a different certificate or key, even if signed by a trusted CA."

##### CWE

- CWE-319 - Cleartext Transmission of Sensitive Information
- CWE-326 - Inadequate Encryption Strength
- CWE-295 - Improper Certificate Validation

##### Nscurl

- A guide to ATS - Blog post by NowSecure - <https://www.nowsecure.com/blog/2017/08/31/security-analysts-guide-nsapptransportsecurity-nsallowsarbitraryloads-app-transport-security-ats-exceptions/>
