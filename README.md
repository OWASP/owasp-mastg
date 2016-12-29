# OWASP Mobile Security Testing Guide

This is the official Github Repository of the OWASP Mobile Security Testing Guide (MSTG). The MSTG is a comprehensive manual for testing the security of mobile apps. It describes technical processes for verifying the controls listed in the [OWASP Mobile Application Verification Standard (MASVS)](https://github.com/OWASP/owasp-masvs). The MSTG is meant to provide a baseline set of test cases for black-box and white-box security tests, and to help ensure completeness and consistency of the tests.

## Table of Contents

The following lists contains the individual sections of the MSTG, along with the person(s) responsible for each section. Please contact them directly to join as an author or give feedback. Another good place to start browsing is the [detailed list of security test cases](all_tests.md). If all you desire is a checklist, you can also download this as an [Excel sheet](Checklist/OWASP-MSTG-Mobile-AppSec-Tests.xlsx).

### Introductionary

- [Header](Document/0x00-Header.md)
- [Foreword](Document/0x01-Foreword.md)
- [Frontispiece](Document/0x02-Frontispiece.md) -- [Bernhard Mueller](https://github.com/b-mueller)
- [The OWASP Mobile Security Project](Document/0x03-The-OWASP-Mobile-Security-Project.md) -- [Bernhard Mueller](https://github.com/b-mueller)

### High-Level Guides

* [Mobile Platforms Overview](Document/0x04-Mobile-Platfoms-Overview.md)
   * [Android](Document/0x04a-Android.md) -- [Cláudio André](https://github.com/clviper)
   * [iOS](Document/0x04b-iOS.md) -- [Looking for Lead Authors](authors_guide.md)
* [Security Testing Processes, Tools and Techniques](Document/0x05-Testing-Processes-and-Techniques.md)
   * [Android](Document/0x05a-Testing-Process-and-Techniques-Android.md) -- [Looking for Lead Authors](https://github.com/OWASP/owasp-mstg/blob/master/authors_guide.md)
   * [iOS](Document/0x05b-Testing-Process-and-Techniques-iOS.md) -- [Looking for Lead Authors](https://github.com/OWASP/owasp-mstg/blob/master/authors_guide.md)
* [Tampering and Reverse Engineering](Document/0x06-Reverse-Engineering-and-Tampering.md) -- [Bernhard Mueller](https://github.com/b-mueller), [Sebastian Banescu](https://github.com/banescusebi)
   * [Android](Document/0x06a-Reverse-Engineering-and-Tampering-Android.md) -- [Bernhard Mueller](https://github.com/b-mueller)
   * [iOS](Document/0x06b-Reverse-Engineering-and-Tampering-iOS.md) -- [Bernhard Mueller](https://github.com/b-mueller)

### Detailed Howtos -> [Full list](all_tests.md)

  * Android
    * [Testing Data Storage](Document/Testcases/0x01a_OMTG-DATAST_Android.md) -- [Francesco Stillavato](https://github.com/litsnarf), [Sven Schleier](https://github.com/sushi2k)
    * [Testing Cryptography](Document/Testcases/0x01b_OMTG-CRYPTO_Android.md) --  [Alexander Antukh](https://github.com/c0rdis), [Gerhard Wagner](https://github.com/thec00n)
    * [Testing Authentication and Session Management](Document/Testcases/0x01c_OMTG-AUTH_Android.md) -- [Daniel Ramirez](https://github.com/ram7rez)
    * [Testing Network Communication](Document/Testcases/0x01d_OMTG-NET_Android.md) -- [Pawel Rzepa](https://github.com/th3g1itch), [Jeroen Willemsen](https://github.com/commjoen)
    * [Testing Environmental Interaction](Document/Testcases/0x01e_OMTG-ENV_Android.md) -- [Sven Schleier](https://github.com/sushi2k)
    * [Testing Code Quality and Build Settings](Document/Testcases/0x01f_OMTG-CODE_Android.md) -- [Abdessamad Temmar](https://github.com/TmmmmmR)
    * [Testing Resiliency Against Reverse Engineering](Document/Testcases/0x01g_OMTG-RARE_Android.md) -- [Bernhard Mueller](https://github.com/b-mueller)
  * iOS
    * [Testing Data Storage](Document/Testcases/0x02a_OMTG-DATAST_iOS.md) -- [Gerhard Wagner](https://github.com/thec00n)
    * [Testing Cryptography](Document/Testcases/0x02b_OMTG-CRYPTO_iOS.md) --  [Alexander Anthuk](https://github.com/c0rdis), [Gerhard Wagner](https://github.com/thec00n)
    * [Testing Authentication and Session Management](Document/Testcases/0x02c_OMTG-AUTH_iOS.md) --  [Daniel Ramirez](https://github.com/ram7rez)
    * [Testing Network Communication](Document/Testcases/0x02d_OMTG-NET_iOS.md) -- [Pawel Rzepa](https://github.com/th3g1itch), [Jeroen Willemsen](https://github.com/commjoen)
    * [Testing Environmental Interaction](Document/Testcases/0x02e_OMTG-ENV_iOS.md) -- [Sven Schleier](https://github.com/sushi2k)
    * [Testing Code Quality and Build Settings](Document/Testcases/0x02f_OMTG-CODE_iOS.md) -- [Abdessamad Temmar](https://github.com/TmmmmmR)
    * [Testing Resiliency Against Reverse Engineering](Document/Testcases/0x02g_OMTG-RARE_iOS.md) -- [Bernhard Mueller](https://github.com/b-mueller)

### Complementary

* [Security Testing in the Application Development Lifecycle](Document/0x07a-Security-Testing-SDLC.md) -- [Stefan Streichsbier](https://github.com/streichsbaer)
* [Assessing the Quality of Software Protections](Document/0x07b_Assessing_Software_Protections.md) -- [Bernhard Mueller](https://github.com/b-mueller)
* [Testing Tools](Document/0x08-Testing-Tools.md) -- [Prathan Phongthiproek](https://github.com/tanprathan/)
* [Suggested Reading](Document/0x09-Suggested-Reading.md) - T.b.d.

## Suggestions and feedback

To report and error or suggest an improvement, please create an [issue](https://github.com/b-mueller/owasp-mstg/issues).

## How to Contribute

**Please read the [author's guide](https://github.com/b-mueller/owasp-mstg/blob/master/authors_guide.md) first if you want to contribute.**

The MSTG is an open source effort and we welcome contributions and feedback. To discuss the MASVS or MSTG join the [OWASP Mobile Security Project Slack Channel](https://owasp.slack.com/messages/project-mobile_omtg/details/). You can sign up here:

http://owasp.herokuapp.com/
