---
masvs_category: MASVS-NETWORK
platform: ios
title: iOS App Transport Security
---

Starting with iOS 9, Apple introduced [App Transport Security (ATS)](https://developer.apple.com/documentation/bundleresources/information_property_list/nsapptransportsecurity) which is a set of security checks enforced by the operating system for connections made using the [URL Loading System](https://developer.apple.com/documentation/foundation/url_loading_system) (typically via `URLSession`) to always use HTTPS. Apps should follow [Apple's best practices](https://developer.apple.com/news/?id=jxky8h89) to properly secure their connections.

> [Watch ATS Introductory Video from the Apple WWDC 2015](https://developer.apple.com/videos/play/wwdc2015/711/?time=321).

ATS performs default server trust evaluation and requires a minimum set of security requirements.

**Default Server Trust Evaluation:**

When an app connects to a remote server, the server provides its identity using an X.509 digital certificate. The ATS default server trust evaluation includes validating that the certificate:

- Isn't expired.
- Has a name that matches the server's DNS name.
- Has a digital signature that is valid (hasn't been tampered with) and can be traced back to a trusted Certificate Authority (CA) included in the [operating system Trust Store](https://support.apple.com/en-us/HT209143), or be installed on the client by the user or a system administrator.

**Minimum Security Requirements for Connections:**

ATS will block connections that further fail to meet a set of [minimum security requirements](https://developer.apple.com/documentation/security/preventing_insecure_network_connections#3138464) including:

- TLS version 1.2 or greater.
- Data encryption with AES-128 or AES-256.
- The certificate must be signed with an RSA key (2048 bits or greater), or an ECC key (256 bits or greater).
- The certificate's fingerprint must use SHA-256 or greater.
- The link must support perfect forward secrecy (PFS) through Elliptic Curve Diffie-Hellman Ephemeral (ECDHE) key exchange.

**Certificate validity checking:**

[According to Apple](https://support.apple.com/en-gb/guide/security/sec100a75d12/web#sec8b087b1f7), "evaluating the trusted status of a TLS certificate is performed in accordance with established industry standards, as set out in RFC 5280, and incorporates emerging standards such as RFC 6962 (Certificate Transparency). In iOS 11 or later, Apple devices are periodically updated with a current list of revoked and constrained certificates. The list is aggregated from certificate revocation lists (CRLs), which are published by each of the built-in root certificate authorities trusted by Apple, as well as by their subordinate CA issuers. The list may also include other constraints at Apple's discretion. This information is consulted whenever a network API function is used to make a secure connection. If there are too many revoked certificates from a CA to list individually, a trust evaluation may instead require that an online certificate status response (OCSP) is needed, and if the response isn't available, the trust evaluation will fail."

## When does ATS not apply?

- **When using lower-level APIs:** ATS only applies to the [URL Loading System](https://developer.apple.com/documentation/foundation/url_loading_system) including [URLSession](https://developer.apple.com/reference/foundation/urlsession) and APIs layered on top of them. It does not apply to apps that use lower-level APIs (like BSD Sockets), including those that implement TLS on top of those lower-level APIs (see section ["Using ATS in Apple Frameworks"](https://developer.apple.com/library/archive/documentation/General/Reference/InfoPlistKeyReference/Articles/CocoaKeys.html#//apple_ref/doc/uid/TP40009251-SW55) from the Archived Apple Developer Documentation).

- **When connecting to IP addresses, unqualified domain names or local hosts:** ATS applies only to connections made to public host names (see section ["Availability of ATS for Remote and Local Connections"](https://developer.apple.com/library/archive/documentation/General/Reference/InfoPlistKeyReference/Articles/CocoaKeys.html#//apple_ref/doc/uid/TP40009251-SW54) from the Archived Apple Developer Documentation). The system does not provide ATS protection to connections made to:
    - Internet protocol (IP) addresses
    - Unqualified host names
    - Local hosts employing the .local top-level domain (TLD)

- **When including ATS Exceptions:** If the app uses the ATS compatible APIs, it can still disable ATS for specific scenarios using [ATS Exceptions](#ats-exceptions).

Learn more:

- ["ATS and iOS enterprise apps with private networks"](https://developer.apple.com/forums/thread/79662)
- ["ATS and local IP addresses"](https://developer.apple.com/forums/thread/66417)
- ["ATS impact on apps use 3rd party libraries"](https://developer.apple.com/forums/thread/69197)
- ["ATS and SSL pinning / own CA"](https://developer.apple.com/forums/thread/53314)

## ATS Exceptions

ATS restrictions can be disabled by configuring exceptions in the `Info.plist` file under the `NSAppTransportSecurity` key. These exceptions can be applied to:

- allow insecure connections (HTTP),
- lower the minimum TLS version,
- disable Perfect Forward Secrecy (PFS) or
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

| Key | Description |
| --------------| ------------|
| `NSAllowsArbitraryLoads` | Disable ATS restrictions globally excepts for individual domains specified under `NSExceptionDomains` |
| `NSAllowsArbitraryLoadsInWebContent` | Disable ATS restrictions for all the connections made from web views |
| `NSAllowsLocalNetworking` | Allow connection to unqualified domain names and .local domains |
| `NSAllowsArbitraryLoadsForMedia` | Disable all ATS restrictions for media loaded through the AV Foundations framework |

The following table summarizes the per-domain ATS exceptions. For more information about these exceptions, please refer to [table 3 in the official Apple developer documentation](https://developer.apple.com/library/content/documentation/General/Reference/InfoPlistKeyReference/Articles/CocoaKeys.html#//apple_ref/doc/uid/TP40009251-SW44 "App Transport Security dictionary primary keys").

| Key | Description |
| --------------| ------------|
| `NSIncludesSubdomains` | Indicates whether ATS exceptions should apply to subdomains of the named domain |
| `NSExceptionAllowsInsecureHTTPLoads` | Allows HTTP connections to the named domain, but does not affect TLS requirements |
| `NSExceptionMinimumTLSVersion` | Allows connections to servers with TLS versions less than 1.2 |
| `NSExceptionRequiresForwardSecrecy` | Disable perfect forward secrecy (PFS) |

**Justifying Exceptions:**

Starting from January 1 2017, Apple App Store review [requires justification](https://developer.apple.com/documentation/security/preventing_insecure_network_connections#3138036) if one of the following ATS exceptions are defined.

- `NSAllowsArbitraryLoads`
- `NSAllowsArbitraryLoadsForMedia`
- `NSAllowsArbitraryLoadsInWebContent`
- `NSExceptionAllowsInsecureHTTPLoads`
- `NSExceptionMinimumTLSVersion`

This must be carefully revised to determine if it's indeed part of the app intended purpose. Apple warns about exceptions reducing the security of the apps and advises to **configure exceptions only when needed and prefer to server fixes** when faced with an ATS failure.

**Example:**

In the following example, ATS is globally enabled (there's no global `NSAllowsArbitraryLoads` defined) but an exception is **explicitly set** for the `example.com` domain (and its subdomains). Considering that the domain is owned by the application developers and there's a proper justification this exception would be acceptable, since it maintains all the benefits of ATS for all other domains. However, it would be always preferable to fix the server as indicated above.

```xml
<key>NSAppTransportSecurity</key>
<dict>
    <key>NSExceptionDomains</key>
    <dict>
        <key>example.com</key>
        <dict>
            <key>NSIncludesSubdomains</key>
            <true/>
            <key>NSExceptionMinimumTLSVersion</key>
            <string>TLSv1.2</string>
            <key>NSExceptionAllowsInsecureHTTPLoads</key>
            <true/>
            <key>NSExceptionRequiresForwardSecrecy</key>
            <true/>
        </dict>
    </dict>
</dict>
```

For more information on ATS exceptions please consult section "Configure Exceptions Only When Needed; Prefer Server Fixes" from the article "Preventing Insecure Network Connections" in the [Apple Developer Documentation](https://developer.apple.com/documentation/security/preventing_insecure_network_connections#3138482) and the [blog post on ATS](https://www.nowsecure.com/blog/2017/08/31/security-analysts-guide-nsapptransportsecurity-nsallowsarbitraryloads-app-transport-security-ats-exceptions/ "A guide to ATS").
