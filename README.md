# OWASP Mobile Security Testing Guide

This is the official Github Repository of the OWASP Mobile Security Testing Guide (MSTG). The MSTG is a comprehensive manual for testing the security of mobile apps. It describes technical processes for verifying the controls listed in the [OWASP Mobile Application Verification Standard (MASVS)](https://github.com/OWASP/owasp-masvs). The MSTG is meant to provide a baseline set of test cases for black-box and white-box security tests, and to help ensure completeness and consistency of the tests.

## Suggestions and feedback

To report and error or suggest an improvement, please create an [issue](https://github.com/b-mueller/owasp-mstg/issues).

# How to Contribute

**Please read the [author's guide](https://github.com/b-mueller/owasp-mstg/blob/master/authors_guide.md) first if you want to contribute.**

The MSTG is an open source effort and we welcome contributions and feedback. To discuss the MASVS or MSTG join the [OWASP Mobile Security Project Slack Channel](https://owasp.slack.com/messages/project-mobile_omtg/details/). You can sign up here:

http://owasp.herokuapp.com/

# MSTG Sections and Lead Authors

The following lists contains the individual sections of the MSTG, along with the person(s) responsible for each section. Please contact them directly to join as an author or give feedback.

* [Header](Document/0x00-Header.md)
* [Foreword](Document/0x01-Foreword.md)
* [Frontispiece](Document/0x02-Frontispiece.md) -- [Bernhard Mueller](https://github.com/b-mueller)
* [The OWASP Moble Application Security Project](Document/0x03-The-OWASP-Mobile-Application-Security-Project.md) -- [Bernhard Mueller](https://github.com/b-mueller)
* [Security Testing in the Application Development Lifecycle](Document/0x07b-Security-Testing-SDLC.md) -- [Stefan Streichsbier](https://github.com/streichsbaer)
* [Mobile Platforms Overview](Document/0x04-Mobile-Platfoms-Overview.md)  --  [Stephen Corbiaux](https://github.com/stephenreda)
    * [Android](Document/0x04a-Android.md) -- [Stephen Corbiaux](https://github.com/stephenreda)
    * [iOS](Document/0x04b-iOS.md) -- [Stephen Corbiaux](https://github.com/stephenreda)
* [Testing Processes and Techniques](Document/0x05-Testing-Processes-and-Techniques.md) -- [Stefanie Vanroelen](https://github.com/grumpysnowwhite), [Stephen Corbiaux](https://github.com/stephenreda)
    * [Android](Document/0x05a-Testing-Process-and-Techniques-Android.md) -- [Stefanie Vanroelen](https://github.com/grumpysnowwhite)
    * [iOS](Document/0x05b-Testing-Process-and-Techniques-iOS.md) -- [Stephen Corbiaux](https://github.com/stephenreda)
* [Reverse Engineering and Tampering](Document/0x06-Reverse-Engineering-and-Tampering.md) -- [Bernhard Mueller](https://github.com/b-mueller)
    * [Android](Document/0x06a-Reverse-Engineering-and-Tampering-Android.md) -- [Bernhard Mueller](https://github.com/b-mueller)
    * [iOS](Document/0x06b-Reverse-Engineering-and-Tampering-iOS.md) -- [Bernhard Mueller](https://github.com/b-mueller)
* [Testing Software Protections](Document/0x07-Assessing-Software-Protections.md) -- [Bernhard Mueller](https://github.com/b-mueller)
* [Testing Data Storage](Document/Testcases/0x00_OMTG-DATAST.md) -- [Francesco Stillavato](https://github.com/litsnarf), [Sven Schleier](https://github.com/sushi2k)
    * [Android](Document/Testcases/0x00a_OMTG-DATAST_Android.md) -- [Francesco Stillavato](https://github.com/litsnarf), [Sven Schleier](https://github.com/sushi2k)
    * [iOS](Document/Testcases/0x00b_OMTG-DATAST_iOS.md) -- [Gerhard Wagner](https://github.com/thec00n)
* [Testing Cryptography](Document/Testcases/0x01_OMTG-CRYPTO.md) --  [Gerhard Wagner](https://github.com/thec00n)
    * [Android](Document/Testcases/0x01a_OMTG-CRYPTO_Android.md) --  [Gerhard Wagner](https://github.com/thec00n)
    * [iOS](Document/Testcases/0x01b_OMTG-CRYPTO_iOS.md) --  [Gerhard Wagner](https://github.com/thec00n)
* [Testing Authentication and Session Management](Document/Testcases/0x02-OMTG-AUTH.md) -- [Stephen Corbiaux](https://github.com/stephenreda)
    * [Android](Document/Testcases/0x02-OMTG-AUTH_Android.md) -- [Stephen Corbiaux](https://github.com/stephenreda)
    * [iOS](Document/Testcases/0x02-OMTG-AUTH_.md) -- [Stephen Corbiaux](https://github.com/stephenreda)
* [Testing Network Communication](Document/Testcases/0x04_OMTG-NET.md) -- [Jeroen Willemsen](https://github.com/commjoen)
    * [Android](Document/Testcases/0x04a_OMTG-NET_Android.md) -- [Jeroen Willemsen](https://github.com/commjoen)
    * [iOS](Document/Testcases/0x04b_OMTG-NET_iOS.md) -- [Jeroen Willemsen](https://github.com/commjoen)
* [Testing Environmental Interaction](Document/0x05_OMTG-ENV.md) -- [Sven Schleier](https://github.com/sushi2k)
    * [Android](Document/Testcases/0x05a_OMTG-ENV_Android.md) -- [Sven Schleier](https://github.com/sushi2k)
    * [iOS](Document/Testcases/0x05b_OMTG-ENV_iOS.md) -- [Sven Schleier](https://github.com/sushi2k)
* [Testing Code Quality and Build Settings](Document/Testcases/0x06_OMTG-CODE.md) -- [Abdessamad Temmar](https://github.com/TmmmmmR)
    * [Android](Document/Testcases/0x06a_OMTG-CODE_Android.md) -- [Abdessamad Temmar](https://github.com/TmmmmmR)
    * [iOS](Document/Testcases/0x06a_OMTG-CODE_Android.md) -- [Abdessamad Temmar](https://github.com/TmmmmmR)
* [Testing Resiliency Against Reverse Engineering](Document/Testcases/0x07_OMTG-RARE.md) -- [Bernhard Mueller](https://github.com/b-mueller)
    * [Android](Document/Testcases/0x07a_OMTG-RARE_Android.md) -- [Bernhard Mueller](https://github.com/b-mueller)
    * [iOS](Document/Testcases/0x07b_OMTG-RARE_iOS.md) -- [Bernhard Mueller](https://github.com/b-mueller)
* [Testing Tools](Document/0x07-Testing-Tools) - T.b.d.
* [Suggested Reading](Document/0x08-Suggested-Reading.md) - T.b.d.
