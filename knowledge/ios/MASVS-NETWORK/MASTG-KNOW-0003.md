---
masvs_category: MASVS-NETWORK
platform: ios
title: iOS Network APIs
---

Since iOS 12.0 the [Network](https://developer.apple.com/documentation/network) framework and the [`URLSession`](https://developer.apple.com/documentation/foundation/urlsession) class provide methods to load network and URL requests asynchronously and synchronously. Older iOS versions can utilize the [Sockets API](https://developer.apple.com/library/archive/documentation/NetworkingInternet/Conceptual/NetworkingTopics/Articles/UsingSocketsandSocketStreams.html).

## Network Framework

The `Network` framework was introduced at [The Apple Worldwide Developers Conference (WWDC)](https://developer.apple.com/videos/play/wwdc2018/715 "Introducing Network.framework: A modern alternative to Sockets") in 2018 and is a replacement to the Sockets API. This low-level networking framework provides classes to send and receive data with built in dynamic networking, security and performance support.

TLS 1.3 is enabled by default in the `Network` framework, if the argument `using: .tls` is used. It is the preferred option over the legacy [Secure Transport](https://developer.apple.com/documentation/security/secure_transport "API Reference Secure Transport") framework.

## URLSession

`URLSession` was built upon the `Network` framework and utilizes the same transport services. The class also uses TLS 1.3 by default, if the endpoint is HTTPS.

**`URLSession` should be used for HTTP and HTTPS connections, instead of utilizing the `Network` framework directly.** The `URLSession` class natively supports both URL schemes and is optimized for such connections. It requires less boilerplate code, reducing the possibility for errors and ensuring secure connections by default. The `Network` framework should only be used when there are low-level and/or advanced networking requirements.

The official Apple documentation includes examples of using the `Network` framework to [implement netcat](https://developer.apple.com/documentation/network/implementing_netcat_with_network_framework "Implementing netcat with Network Framework") and `URLSession` to [fetch website data into memory](https://developer.apple.com/documentation/foundation/url_loading_system/fetching_website_data_into_memory "Fetching Website Data into Memory").
