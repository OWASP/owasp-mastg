# Assessment and Certification

## OWASP's Stance on MASVS Certifications and Trust Marks

OWASP, as a vendor-neutral not-for-profit organization, does not certify any vendors, verifiers or software.

All such assurance assertions, trust marks, or certifications are not officially vetted, registered, or certified by OWASP, so an organization relying upon such a view needs to be cautious of the trust placed in any third party or trust mark claiming (M)ASVS certification.

This should not inhibit organizations from offering such assurance services, as long as they do not claim official OWASP certification.

## Guidance for Certifying Mobile Apps

The recommended way of verifying compliance of a mobile app with the MASVS is by performing an "open book" review, meaning that the testers are granted access to key resources such as architects and developers of the app, project documentation, source code, and authenticated access to endpoints, including access to at least one user account for each role.

It is important to note that the MASVS only covers the security of the  mobile app (client-side). It does not contain specific controls for the remote endpoints (e.g. web services) associated with the app and they should be verified against appropriate standards, such as the [OWASP ASVS](https://owasp.org/www-project-application-security-verification-standard/).

A certifying organization must include in any report the scope of the verification (particularly if a key component is out of scope), a summary of verification findings, including passed and failed tests, with clear indications of how to resolve the failed tests. Keeping detailed work papers, screenshots or recording, scripts to reliably and repeatedly exploit an issue, and electronic records of testing, such as intercepting proxy logs and associated notes such as a cleanup list, is considered standard industry practice. It is not sufficient to simply run a tool and report on the failures; this does not provide sufficient evidence that all issues at a certifying level have been tested and tested thoroughly. In case of dispute, there should be sufficient supportive evidence to demonstrate that every verified control has indeed been tested.

### Using the OWASP Mobile Application Security Testing Guide (MASTG)

The [OWASP MASTG](https://mas.owasp.org/MASTG/) is a manual for testing the security of mobile apps. It describes the technical processes for verifying the controls listed in the MASVS. The MASTG includes a list of test cases, each of which map to a control in the MASVS. While the MASVS controls are high-level and generic, the MASTG provides in-depth recommendations and testing procedures on a per-mobile-OS basis.

Testing the app's remote endpoints is not covered in the MASTG. For example:

- **Remote Endpoints**: The [OWASP Web Security Testing Guide (WSTG)](https://owasp.org/www-project-web-security-testing-guide/) is a comprehensive guide with detailed technical explanation and guidance for testing the security of web applications and web services holistically and can be used in addition to other relevant resources to complement the mobile app security testing exercise.
- **Internet of Things (IoT)**: The [OWASP IoT Security Testing Guide (ISTG)](https://owasp.org/owasp-istg/) provides a comprehensive methodology for penetration tests in the IoT field offering flexibility to adapt innovations and developments on the IoT market while still ensuring comparability of test results. The guide provides an understanding of communication between manufacturers and operators of IoT devices as well as penetration testing teams that's facilitated by establishing a common terminology.

### The Role of Automated Security Testing Tools

The use of source code scanners and black-box testing tools is encouraged in order to increase efficiency whenever possible. It is however not possible to complete MASVS verification using automated tools alone, since every mobile app is different. In order to fully verify the security of the app it is essential to understand the overall architecture, business logic, and technical pitfalls of the specific technologies and frameworks being used.

## Other Uses

### As Detailed Security Architecture Guidance

One of the more common uses for the Mobile Application Security Verification Standard is as a resource for security architects. The two major security architecture frameworks, SABSA or TOGAF, are missing a great deal of information that is necessary to complete mobile application security architecture reviews. MASVS can be used to fill in those gaps by allowing security architects to choose better controls for issues common to mobile apps.

### As a Replacement for Off-the-shelf Secure Coding Checklists

Many organizations can benefit from adopting the MASVS, by choosing one of the two levels, or by forking MASVS and changing what is required for each application's risk level in a domain-specific way. We encourage this type of forking as long as traceability is maintained, so that if an app has passed control 4.1, this means the same thing for forked copies as the standard evolves.

### As a Basis for Security Testing Methodologies

A good mobile app security testing methodology should cover all controls listed in the MASVS. The OWASP Mobile Application Security Testing Guide (MASTG) describes black-box and white-box test cases for each verification control.

### As a Guide for Automated Unit and Integration Tests

The MASVS is designed to be highly testable, with the sole exception of architectural controls. Automated unit, integration and acceptance testing based on the MASVS controls can be integrated in the continuous development lifecycle. This not only increases developer security awareness, but also improves the overall quality of the resulting apps, and reduces the amount of findings during security testing in the pre-release phase.

### For Secure Development Training

MASVS can also be used to define characteristics of secure mobile apps. Many "secure coding" courses are simply ethical hacking courses with a light smear of coding tips. This does not help developers. Instead, secure development courses can use the MASVS, with a strong focus on the proactive controls documented in the MASVS, rather than e.g. the Top 10 code security issues.
