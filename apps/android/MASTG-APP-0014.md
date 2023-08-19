---
title: InsecureShop
platform: android
ref:
- https://github.com/hax0rgb/InsecureShop/
---

InsecureShop is an intentionally designed Android application that showcases vulnerabilities, aiming to educate developers and security experts about common pitfalls within modern Android apps. It serves as a dynamic platform for refining Android pentesting skills.

The majority of these vulnerabilities can be exploited on non-rooted devices, posing risks from both remote users and malicious third-party applications. Notably, the app doesn't utilize any APIs. InsecureShop presents an opportunity to explore a range of vulnerabilities:

- **Hardcoded Credentials**: Embedded login credentials within the code.
- **Insufficient URL Validation**: Allows loading of arbitrary URLs via Deeplinks.
- **Arbitrary Code Execution**: Enables the execution of code from third-party packages.
- **Access to Protected Components**: Permits third-party apps to launch secure components.
- **Insecure Broadcast Receiver**: Registration of a broadcast enabling URL injection.
- **Insecure Content Provider**: Accessible content provider putting user data at risk.

Complementing these learning experiences, InsecureShop provides [documentation](https://docs.insecureshopapp.com/ "InsecureShop Docs") about the implemented vulnerabilities and their associated code. This documentation, however, refrains from offering complete solutions for each vulnerability showcased within the InsecureShop app.
