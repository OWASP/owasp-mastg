# OWASP Mobile Security Testing Guide

This is the official Github Repository of the OWASP Mobile Security Testing Guide (MSTG). The MSTG is a comprehensive manual for testing the security of mobile apps. It describes technical processes for verifying the controls listed in the [OWASP Mobile Application Verification Standard (MASVS)](https://github.com/OWASP/owasp-masvs). The MSTG is meant to provide a baseline set of test cases for black-box and white-box security tests, and to help ensure completeness and consistency of the tests.

## Table of Contents

Use the [document index](https://rawgit.com/OWASP/owasp-mstg/master/Generated/OWASP-MSTG-Table-of-Contents.html) to navigate the master branch of the MSTG.

## High-Level Structure

The following lists contains the individual sections of the MSTG, along with the main contact persons responsible for each section. Please contact them directly to join as an author or give feedback. Another good place to start browsing is the [document index](https://rawgit.com/OWASP/owasp-mstg/master/Generated/OWASP-MSTG-Table-of-Contents.html). If all you desire is a checklist, you can also download this as an [Excel sheet](Checklists/OWASP-MSTG-Mobile-AppSec-Tests.xlsx).

### Introductionary

- [Header](Document/0x00-Header.md)
- [Foreword](Document/0x01-Foreword.md)
- [Frontispiece](Document/0x02-Frontispiece.md)

Main Contact: [Bernhard Mueller](https://github.com/b-mueller)

### Overview

* [Overview](0x03-Overview.md)
* [Testing Processes and Techniques](Document/0x04-Testing-Processes-and-Techniques.md)

Main Contacts: [Pishu Mahtani](https://github.com/mpishu) - Slack: *pmathani*, [Bernhard Mueller](https://github.com/b-mueller) - Slack: *berhardm*

### Android Testing Guide

- [Platform Overview](Document/0x05a-Platform-Overview.md) -- [Cláudio André](https://github.com/clviper) - *clviper*, [Romuald Szkudlarek](https://github.com/romualdszkudlarek) - *romualds*
- [Basic Security Testing on Android](Document/0x05b-Basic-Security_Testing.md) -- [Luander Ribeiro](https://github.com/luander) - *luander*, [Sven Schleier](https://github.com/sushi2k) - *sushi2k*
- [Tampering and Reverse Engineering on Android](Document/0x05b-Reverse-Engineering-and-Tampering.md) -- [Bernhard Mueller](https://github.com/b-mueller) - *bernhardm*
- [Testing Data Storage](Document/0x05d-Testing-Data-Storage.md) -- [Francesco Stillavato](https://github.com/litsnarf) - *litsnarf*, [Sven Schleier](https://github.com/sushi2k) - *sushi2k*
- [Testing Cryptography](Document/0x05e-Testing-Cryptography.md) --  [Alexander Antukh](https://github.com/c0rdis) - *alex*, [Gerhard Wagner](https://github.com/thec00n) - *bernhardm*
- [Testing Authentication and Session Management](Document/0x05f-Testing-Authentication.md) -- [Daniel Ramirez](https://github.com/ram7rez)
- [Testing Network Communication](Document/0x05g-Testing-Network-Communication.md) -- [Pawel Rzepa](https://github.com/th3g1itch) - *xep624*, [Jeroen Willemsen](https://github.com/commjoen) - *jeroenwillemsen*
- [Testing Environmental Interaction](Document/0x05h-Testing-Platform-Interaction.md) -- [Sven Schleier](https://github.com/sushi2k) - *sushi2k*
- [Testing Code Quality and Build Settings](Document/0x05i-Testing-Code-Quality-and-Build-Settings.md) -- [Abdessamad Temmar](https://github.com/TmmmmmR) - *temmar*
- [Testing Resiliency Against Reverse Engineering](Document/0x05j-Testing-Resiliency-Against-Reverse-Engineering.md) -- [Bernhard Mueller](https://github.com/b-mueller) - *bernhardm*

### iOS Testing Guide

- [Platform Overview](Document/0x06a-Platform-Overview.md) -- [Pishu Mahtani](https://github.com/mpishu) - *pmathani*
- [Basic Security Testing on iOS](Document/0x06b-Basic-Security-Testing.md) -- [Sven Schleier](https://github.com/sushi2k) - *sushi2k*
- [Tampering and Reverse Engineering on iOS](Document/0x06c-Reverse-Engineering-and-Tampering.md) -- [Bernhard Mueller](https://github.com/b-mueller) - *bernhardm*
- [Testing Data Storage](Document/0x06d-Testing-Data-Storage.md) -- [Gerhard Wagner](https://github.com/thec00n) - *bernhardm*
- [Testing Cryptography](Document/0x06e-Testing-Cryptography.md) --  [Alexander Anthuk](https://github.com/c0rdis) - *alex*, [Gerhard Wagner](https://github.com/thec00n) - *bernhardm*
- [Testing Authentication and Session Management](Document/0x06f-Testing-Authentication-and-Session-Management.md) --  [Daniel Ramirez](https://github.com/ram7rez)
- [Testing Network Communication](Document/0x06g-Testing-Network-Communication.md) -- [Pawel Rzepa](https://github.com/th3g1itch), [Jeroen Willemsen](https://github.com/commjoen) - *jeroenwillemsen*
- [Testing Platform Interaction](Document/0x06h-Testing-Platform-Interaction.md) -- [Sven Schleier](https://github.com/sushi2k) - *sushi2k*
- [Testing Code Quality and Build Settings](Document/0x06i-Testing-Code-Quality-and-Build-Settings.md) -- [Abdessamad Temmar](https://github.com/TmmmmmR) - *temmar*
- [Testing Resiliency Against Reverse Engineering](Document/0x06j-Testing-Resiliency-Against-Reverse-Engineering.md) -- [Bernhard Mueller](https://github.com/b-mueller) - *bernhardm*

### Appendix

* [Security Testing in the Application Development Lifecycle](Document/0x07-Security-Testing-SDLC.md) -- [Stefan Streichsbier](https://github.com/streichsbaer)- *stefan*
* [Testing Tools](Document/0x08-Testing-Tools.md) -- [Prathan Phongthiproek](https://github.com/tanprathan/) - *tan_prathan*
* [Suggested Reading](Document/0x09-Suggested-Reading.md) - N/A

## Suggestions and feedback

To report an error or suggest an improvement, please create an [issue](https://github.com/b-mueller/owasp-mstg/issues), or do a pull request.

## How to Contribute

**Please read the [author's guide](https://github.com/b-mueller/owasp-mstg/blob/master/authors_guide.md) first if you want to contribute.**

The MSTG is an open source effort and we welcome contributions and feedback. To discuss the MASVS or MSTG join the [OWASP Mobile Security Project Slack Channel](https://owasp.slack.com/messages/project-mobile_omtg/details/). You can sign up here:

http://owasp.herokuapp.com/
