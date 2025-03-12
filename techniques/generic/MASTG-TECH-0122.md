---
title: Passive Eavesdropping
platform: generic
---

This method involves passively capturing network traffic using tools such as @MASTG-TOOL-0081, @MASTG-TOOL-0080, or @MASTG-TOOL-0075. It is useful for identifying network endpoints, analyzing protocol metadata, and understanding how an app communicates with its server. However, it cannot automatically decrypt TLS-encrypted communication. That said, [TLS decryption is possible](https://wiki.wireshark.org/TLS#tls-decryption) if you can [obtain the pre-master secret](https://wiki.wireshark.org/TLS#using-the-pre-master-secret). For an example specific to Android, see [this article](https://nibarius.github.io/learning-frida/2022/05/21/sniffing-tls-traffic).

## When Is it Useful?

Passive eavesdropping is particularly useful in the following scenarios:

- **Troubleshooting active MITM issues**: Identifying TLS handshake errors, certificate validation failures, and routing anomalies that may cause active interception techniques to fail.
- **Analyzing plaintext non-HTTP traffic**: Monitoring protocols such as XMPP, MQTT, DNS, SMB, and custom UDP/TCP protocols used by the app. Also useful for analyzing push notification traffic from services like Google Cloud Messaging (GCM) / Firebase Cloud Messaging (FCM) on Android or Apple Push Notification Service (APNS) on iOS.
- **Analyzing traffic from non-proxy-aware apps**: Some mobile apps ignore system proxy settings (e.g., those built with [Xamarin](https://www.xamarin.com/platform "Xamarin")) or actively detect and block MITM proxies. Passive eavesdropping allows monitoring without triggering detection mechanisms.
- **Investigating network anomalies and unintended data leaks**: Passive monitoring can help detect unexpected third-party communication, data leakage via DNS requests, or unusual outbound connections. Additionally, even if TLS encryption prevents direct payload inspection, metadata leaks (e.g., request size, timing patterns, domain names, or packet sequences) can still provide valuable insights and may be useful for side-channel attacks.

## How Does It Work?

Passive eavesdropping can be performed in two ways:

1. **Directly on a rooted Android or jailbroken iOS device**
   If the device is rooted (Android) or jailbroken (iOS), you can capture network traffic directly using `tcpdump` or similar tools, without needing a host computer. This allows you to monitor all outgoing and incoming packets in real time.

2. **By routing traffic through a host computer (works on both rooted/jailbroken and non-rooted/non-jailbroken devices)**
   If direct packet capture on the device is not possible or preferred, you can route its network traffic to a host computer and analyze it using tools like @MASTG-TOOL-0081 or @MASTG-TOOL-0075. This method applies to **both rooted/jailbroken and non-rooted/non-jailbroken devices** and is typically achieved through:
   - **Using an interception proxy** to intercept and analyze HTTP/S traffic.
   - **Setting up a VPN-based capture** to redirect traffic through a controlled network tunnel.
   - **Performing ARP spoofing or setting up a transparent network tap** on a Wi-Fi network.

## Per-Platform Instructions

- **Android:** @MASTG-TECH-0010
- **iOS:** @MASTG-TECH-0062
