---
title: badssl
platform: network
source: https://github.com/chromium/badssl.com
---

[badssl.com](https://badssl.com/) is a website maintained by the Chromium project that provides various SSL/TLS certificate configurations for testing security implementations. It offers a comprehensive collection of test subdomains with different certificate issues and configurations to help developers and security testers validate how applications handle SSL/TLS certificate validation.

The tool provides test cases for common SSL/TLS vulnerabilities and misconfigurations, including:

- Self-signed certificates (`self-signed.badssl.com`)
- Expired certificates (`expired.badssl.com`)
- Wrong hostname certificates (`wrong.host.badssl.com`)
- Untrusted root certificates (`untrusted-root.badssl.com`)
- Mixed content scenarios (`mixed.badssl.com`)
- Weak cipher suites (`rc4.badssl.com`, `dh512.badssl.com`)
- HSTS testing (`hsts.badssl.com`)
- Certificate transparency issues (`no-sct.badssl.com`)

This makes badssl.com particularly useful for testing the SSL/TLS certificate validation logic of mobile applications and ensuring that they properly reject invalid certificates and handle various security scenarios correctly.
