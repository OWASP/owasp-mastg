---
masvs_category: MASVS-NETWORK
platform: ios
title: Server Trust Evaluation
---

ATS imposes extended security checks that supplement the default server trust evaluation prescribed by the Transport Layer Security (TLS) protocol. Loosening ATS restrictions reduces the security of the app. Apps should prefer alternative ways to improve server security before adding ATS exceptions.

The [Apple Developer Documentation](https://developer.apple.com/documentation/security/preventing_insecure_network_connections) explains that an app can use `URLSession` to automatically handle server trust evaluation. However, apps are also able to customize that process, for example they can:

- bypass or customize certificate expiry.
- loosen/extend trust: accept server credentials that would otherwise be rejected by the system, e.g. to make secure connections to a development server using self-signed certificates embedded in the app.
- tighten trust: reject credentials that would otherwise be accepted by the system.
- etc.

<img src="Images/Chapters/0x06g/manual-server-trust-evaluation.png" width="100%" />

References:

- [Preventing Insecure Network Connections](https://developer.apple.com/documentation/security/preventing_insecure_network_connections)
- [Performing Manual Server Trust Authentication](https://developer.apple.com/documentation/foundation/url_loading_system/handling_an_authentication_challenge/performing_manual_server_trust_authentication)
- [Certificate, Key, and Trust Services](https://developer.apple.com/documentation/security/certificate_key_and_trust_services)
