---
masvs_v1_id:
- MSTG-NETWORK-1
masvs_v2_id:
- MASVS-NETWORK-1
platform: ios
title: Testing Data Encryption on the Network
masvs_v1_levels:
- L1
- L2
profiles: [L1, L2]
---

## Overview

All the presented cases must be carefully analyzed as a whole. For example, even if the app does not permit cleartext traffic in its Info.plist, it might actually still be sending HTTP traffic. That could be the case if it's using a low-level API (for which ATS is ignored) or a badly configured cross-platform framework.

> IMPORTANT: You should apply these tests to the app main code but also to any app extensions, frameworks or Watch apps embedded within the app as well.

For more information refer to the article ["Preventing Insecure Network Connections"](https://developer.apple.com/documentation/security/preventing_insecure_network_connections) and ["Fine-tune your App Transport Security settings"](https://developer.apple.com/news/?id=jxky8h89) in the Apple Developer Documentation.

## Static Analysis

### Testing Network Requests over Secure Protocols

First, you should identify all network requests in the source code and ensure that no plain HTTP URLs are used. Make sure that sensitive information is sent over secure channels by using [`URLSession`](https://developer.apple.com/documentation/foundation/urlsession) (which uses the standard [URL Loading System from iOS](https://developer.apple.com/documentation/foundation/url_loading_system)) or [`Network`](https://developer.apple.com/documentation/network) (for socket-level communication using TLS and access to TCP and UDP).

### Check for Low-Level Networking API Usage

Identify the network APIs used by the app and see if it uses any low-level networking APIs.

> **Apple Recommendation: Prefer High-Level Frameworks in Your App**: "ATS doesn't apply to calls your app makes to lower-level networking interfaces like the Network framework or CFNetwork. In these cases, you take responsibility for ensuring the security of the connection. You can construct a secure connection this way, but mistakes are both easy to make and costly. It's typically safest to rely on the URL Loading System instead" (see [source](https://developer.apple.com/documentation/security/preventing_insecure_network_connections)).

If the app uses any low-level APIs such as [`Network`](https://developer.apple.com/documentation/network) or [`CFNetwork`](https://developer.apple.com/documentation/cfnetwork), you should carefully investigate if they are being used securely. For apps using cross-platform frameworks (e.g. Flutter, Xamarin, ...) and third party frameworks (e.g. Alamofire) you should analyze if they're being configured and used securely according to their best practices.

Make sure that the app:

- verifies the challenge type and the host name and credentials when performing server trust evaluation.
- doesn't ignore TLS errors.
- doesn't use any insecure TLS configurations (see @MASTG-TEST-0066)

These checks are orientative, we cannot name specific APIs since every app might use a different framework. Please use this information as a reference when inspecting the code.

### Testing for Cleartext Traffic

Ensure that the app is not allowing cleartext HTTP traffic. Since iOS 9.0 cleartext HTTP traffic is blocked by default (due to App Transport Security (ATS)) but there are multiple ways in which an application can still send it:

- Configuring ATS to enable cleartext traffic by setting the `NSAllowsArbitraryLoads` attribute to `true` (or `YES`) on `NSAppTransportSecurity` in the app's `Info.plist`.
- Retrieve the `Info.plist` (see @MASTG-TECH-0058)
- Check that `NSAllowsArbitraryLoads` is not set to `true` globally of for any domain.

- If the application opens third party web sites in WebViews, then from iOS 10 onwards `NSAllowsArbitraryLoadsInWebContent` can be used to disable ATS restrictions for the content loaded in web views.

> **Apple warns:** Disabling ATS means that unsecured HTTP connections are allowed. HTTPS connections are also allowed, and are still subject to default server trust evaluation. However, extended security checks—like requiring a minimum Transport Layer Security (TLS) protocol version—are disabled. Without ATS, you're also free to loosen the default server trust requirements, as described in ["Performing Manual Server Trust Authentication"](https://developer.apple.com/documentation/foundation/url_loading_system/handling_an_authentication_challenge/performing_manual_server_trust_authentication).

The following snippet shows a **vulnerable example** of an app disabling ATS restrictions globally.

```xml
<key>NSAppTransportSecurity</key>
<dict>
    <key>NSAllowsArbitraryLoads</key>
    <true/>
</dict>
```

ATS should be examined taking the application's context into consideration. The application may _have to_ define ATS exceptions to fulfill its intended purpose. For example, the [Firefox iOS application has ATS disabled globally](https://github.com/mozilla-mobile/firefox-ios/blob/v97.0/Client/Info.plist#L82). This exception is acceptable because otherwise the application would not be able to connect to any HTTP website that does not have all the ATS requirements. In some cases, apps might disable ATS globally but enable it for certain domains to e.g. securely load metadata or still allow secure login.

ATS should include a [justification string](https://developer.apple.com/documentation/security/preventing_insecure_network_connections#3138036) for this (e.g. "The app must connect to a server managed by another entity that doesn't support secure connections.").

## Dynamic Analysis

Intercept the tested app's incoming and outgoing network traffic and make sure that this traffic is encrypted. You can intercept network traffic in any of the following ways:

- Capture all HTTP(S) and Websocket traffic with an interception proxy like @MASTG-TOOL-0079 or @MASTG-TOOL-0077 and make sure all requests are made via HTTPS instead of HTTP.
- Interception proxies like Burp and @MASTG-TOOL-0079 will show web related traffic primarily (e.g. HTTP(S), Web Sockets, gRPC, etc.). You can, however, use a Burp plugin such as [Burp-non-HTTP-Extension](https://github.com/summitt/Burp-Non-HTTP-Extension "Burp-non-HTTP-Extension") or the tool [mitm-relay](https://github.com/jrmdev/mitm_relay "mitm-relay") to decode and visualize communication via XMPP and other protocols.

> Some applications may not work with proxies like Burp and ZAP because of Certificate Pinning. In such a scenario, please check @MASTG-TEST-0068.

For more details refer to:

- ["Intercepting Network Traffic Through MITM"](../../../Document/0x04f-Testing-Network-Communication.md#intercepting-network-traffic-through-mitm)
- @MASTG-TECH-0062
