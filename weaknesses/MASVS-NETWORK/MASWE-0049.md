---
title: Proven Networking APIs Not used
id: MASWE-0049
alias: no-proven-net-apis
platform: [android, ios]
profiles: [L2]
mappings:
  masvs-v1: [MSTG-NETWORK-6]
  masvs-v2: [MASVS-NETWORK-1, MASVS-CODE-3]
status: new
---

## Overview

Applications that do not utilize platform-provided networking APIs or well-established security libraries are susceptible to security vulnerabilities. When developers implement custom networking code or "roll-your-own" security mechanisms, they risk introducing flaws due to a lack of deep expertise in cryptography and network security. Platform-provided APIs and libraries, such as `NSURLSession` on iOS or `HttpsURLConnection` on Android, are designed and maintained by experts, incorporating security best practices and regular updates to address new threats and vulnerabilities.

## Impact

- **Security Vulnerabilities**: Custom networking implementations may contain flaws that attackers can exploit, leading to data breaches and unauthorized access.
- **Lack of Updates**: Custom code may not receive timely updates to address new vulnerabilities or comply with evolving security standards.
- **Inconsistent Security Measures**: Bypassing standard APIs can result in inconsistent application of security features like encryption, certificate validation, and error handling.
- **Increased Development Complexity**: Writing and maintaining custom networking code increases complexity, making it harder to audit and secure the application.
- **Non-Compliance with Standards**: Failing to use approved APIs may lead to non-compliance with industry regulations and security guidelines.

## Modes of Introduction

- **Custom Networking Stack Development**: Developers create their own networking code instead of using platform-provided APIs, possibly to add custom features or due to unfamiliarity with existing APIs.
- **Use of Insecure Third-Party Libraries**: Incorporating third-party networking libraries that are outdated or do not follow current security best practices.
- **Bypassing Security Mechanisms**: Deliberately avoiding standard APIs to circumvent security checks, such as certificate pinning or TLS enforcement.
- **Insufficient Security Knowledge**: Developers may lack adequate understanding of network security principles, leading to insecure implementations.
- **Performance Optimization Attempts**: Writing custom networking code to optimize performance without fully considering the security implications.

## Mitigations

- **Utilize Platform-Provided Networking APIs**: Always use the networking APIs provided by the platform, such as `NSURLSession` for iOS and `HttpsURLConnection` for Android, which handle many security concerns internally.
- **Adopt Established Security Libraries**: If additional functionality is required, use reputable, well-maintained libraries like `OkHttp` for Android or `Alamofire` on iOS  that adhere to security best practices.
- **Avoid Custom Security Implementations**: Refrain from implementing custom cryptographic algorithms or security protocols; rely on standard, vetted solutions instead.
- **Keep Dependencies Updated**: Regularly update all libraries and dependencies to incorporate the latest security patches and improvements.
