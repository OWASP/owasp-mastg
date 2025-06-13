---
title: Intercepting Non-HTTP Traffic Using an Interception Proxy
platform: generic
---

Interception proxies such as @MASTG-TOOL-0077 and @MASTG-TOOL-0079 won't show non-HTTP traffic, because they aren't capable of decoding it properly by default. They can, however, be extended using the following tools, allowing you to intercept and manipulate non-HTTP traffic:

- [Burp-non-HTTP-Extension](https://github.com/summitt/Burp-Non-HTTP-Extension "Burp-non-HTTP-Extension") and
- [Mitm-relay](https://github.com/jrmdev/mitm_relay "Mitm-relay").

Note that this setup can sometimes become very tedious and is not as straightforward as testing HTTP.
