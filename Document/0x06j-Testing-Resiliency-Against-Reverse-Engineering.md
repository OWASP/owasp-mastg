---
masvs_category: MASVS-RESILIENCE
platform: ios
---

# iOS Anti-Reversing Defenses

## Overview

This chapter covers defense-in-depth measures recommended for apps that process, or give access to, sensitive data or functionality. Research shows that [many App Store apps often include these measures](https://seredynski.com/articles/a-security-review-of-1-300-appstore-applications "A security review of 1,300 AppStore applications - 5 April 2020").

These measures should be applied as needed, based on an assessment of the risks caused by unauthorized tampering with the app and/or reverse engineering of the code.

- Apps must never use these measures as a replacement for security controls, and are therefore expected to fulfill other baseline security measures such as the rest of the MASVS security controls.
- Apps should combine these measures cleverly instead of using them individually. The goal is to discourage reverse engineers from performing further analysis.
- Integrating some of the controls into your app might increase the complexity of your app and even have an impact on its performance.

You can learn more about principles and technical risks of reverse engineering and code modification in these OWASP documents:

- [OWASP Architectural Principles That Prevent Code Modification or Reverse Engineering](https://wiki.owasp.org/index.php/OWASP_Reverse_Engineering_and_Code_Modification_Prevention_Project "OWASP Architectural Principles That Prevent Code Modification or Reverse Engineering")
- [OWASP Technical Risks of Reverse Engineering and Unauthorized Code Modification](https://wiki.owasp.org/index.php/Technical_Risks_of_Reverse_Engineering_and_Unauthorized_Code_Modification "OWASP Technical Risks of Reverse Engineering and Unauthorized Code Modification")

**General Disclaimer:**

The **lack of any of these measures does not cause a vulnerability** - instead, they are meant to increase the app's resilience against reverse engineering and specific client-side attacks.

None of these measures can assure a 100% effectiveness, as the reverse engineer will always have full access to the device and will therefore always win (given enough time and resources)!

For example, preventing debugging is virtually impossible. If the app is publicly available, it can be run on an untrusted device that is under full control of the attacker. A very determined attacker will eventually manage to bypass all the app's anti-debugging controls by patching the app binary or by dynamically modifying the app's behavior at runtime with tools such as Frida.

The techniques discussed below will allow you to detect various ways in which an attacker may target your app. Since these techniques are publicly documented, they are generally easy to bypass. Using open-source detection techniques is a good first step in improving the resiliency of your app, but standard anti-detection tools can easily bypass them. Commercial products typically offer higher resilience, as they will combine multiple techniques, such as:

- Using undocumented detection techniques
- Implementing the same techniques in various ways
- Triggering the detection logic in different scenarios
- Providing unique detection combinations per build
- Working together with a backend component for additional verification and HTTP payload encryption
- Communicating the detection status to the backend
- Advanced static obfuscation
