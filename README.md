# OWASP Mobile Security Testing Guide

This is the official Github Repository of the OWASP Mobile Security Testing Guide (MSTG). The MSTG is a comprehensive manual for testing the security of mobile apps. It describes technical processes for verifying the controls listed in the [OWASP Mobile Application Verification Standard (MASVS)](https://github.com/OWASP/owasp-masvs). The MSTG provides a baseline set of test cases for black-box and white-box security tests, ensuring completeness and consistency of the tests.

## Reading the Mobile Security Testing Guide

The MSTG doesn't have an official release. There are, however, several options to convert it into an easily readable format:

1. Read it on [Gitbook](https://b-mueller.gitbooks.io/owasp-mobile-security-testing-guide/content/). The book is auto-synced with the main repo. You can use Gitbook to generate PDF, epub, and other e-book formats.

2. Clone the repository and run the [document generator](https://github.com/OWASP/owasp-mstg/blob/master/Tools/generate_document.sh) (requires [pandoc](http://pandoc.org)). This produces docx and html files in the "Generated" subdirectory.

You can also use the [document index](https://rawgit.com/OWASP/owasp-mstg/master/Generated/OWASP-MSTG-Table-of-Contents.html) to navigate the master branch of the MSTG.

## Contributions and Feedback

We need more authors! The best way to get started is to browse the [existing content](https://b-mueller.gitbooks.io/owasp-mobile-security-testing-guide/content/). Also, check the [Project dashboard](https://github.com/OWASP/owasp-mstg/projects/1) for a list of open tasks including authoring, review and technical editing. To sign up for any of those tasks, simply comment on the respective [issue](https://github.com/OWASP/owasp-mstg/labels/help%20wanted) and/or contact us on [Slack](https://owasp.slack.com/messages/project-mobile_omtg/details/). You can create a Slack account here:

http://owasp.herokuapp.com/

Before you start contributing, please also read our brief [style guide](https://github.com/OWASP/owasp-mstg/blob/master/style_guide.md) which contains a few basic writing rules.

You can also suggest improvements by creating an [issue](https://github.com/OWASP/owasp-mstg/issues) on GitHub or a pull request (actually, pull requests are the preferred choice).

## Authoring Credit

Contributors are added to the acknowledgements table based on their contributions logged by GitHub. The list of names is sorted by the number of lines added. Authors are categorized as follows:

- Project Leader / Author: Manage development of the guide continuosly and write a large amount of content.
- Co-Author: Consistently contribute quality content, [at least 500 additions logged](https://github.com/OWASP/owasp-mstg/graphs/contributors).
- Top Contributor: Consistently contribute quality content, [at least 100 additions logged](https://github.com/OWASP/owasp-mstg/graphs/contributors).
- Contributor: Any form of contribution, [at least 1 addition logged](https://github.com/OWASP/owasp-mstg/graphs/contributors).
- Reviewer: People that haven't submitted their own pull requests, but have created issues or given useful feedback in other ways. 

Please ping us or create a pull request if you are missing from the table or in the wrong column (note that we update the table frequently, but not in realtime).

If you are willing to write a large portion of the guide and help consistently drive the project forward, you can join as an author. Be aware that you'll be expected to invest lots of time over several months. Contact [Bernhard Mueller](https://github.com/b-mueller) (Slack: *bernhardm*) for more information.

## High-Level Structure

The following lists contain the individual sections of the MSTG, along with the main contacts responsible for each section. For a detailed lists of all headings see the [document index](https://rawgit.com/OWASP/owasp-mstg/master/Generated/OWASP-MSTG-Table-of-Contents.html). If all you desire is a checklist, download the magic [Excel sheet](https://github.com/OWASP/owasp-mstg/raw/master/Checklists/Mobile_App_Security_Checklist.xlsx).

### Introductionary

- [Header](Document/0x00-Header.md)
- [Foreword](Document/Foreword.md)
- [Frontispiece](Document/0x02-Frontispiece.md)

Main Contact: [Bernhard Mueller](https://github.com/b-mueller) - Slack: *bernhardm*

### Overview

* [Introduction to the Mobile Security Testing Guide](Document/0x03-Overview.md)
* [Testing Processes and Techniques](Document/0x04-Testing-Processes-and-Techniques.md)

Main Contacts: [Bernhard Mueller](https://github.com/b-mueller) - Slack: *bernhardm*

### Android Testing Guide

- [Platform Overview](Document/0x05a-Platform-Overview.md) -- [Romuald Szkudlarek](https://github.com/romualdszkudlarek) - *romualds*
- [Basic Security Testing on Android](Document/0x05b-Basic-Security_Testing.md) -- [Luander Ribeiro](https://github.com/luander) - *luander*, [Sven Schleier](https://github.com/sushi2k) - *sushi2k*
- [Tampering and Reverse Engineering on Android](Document/0x05c-Reverse-Engineering-and-Tampering.md) -- [Bernhard Mueller](https://github.com/b-mueller) - *bernhardm*
- [Testing Data Storage](Document/0x05d-Testing-Data-Storage.md) -- [Francesco Stillavato](https://github.com/litsnarf) - *litsnarf*, [Sven Schleier](https://github.com/sushi2k) - *sushi2k*
- [Testing Cryptography](Document/0x05e-Testing-Cryptography.md) --  [Alexander Antukh](https://github.com/c0rdis) - *alex*
- [Testing Authentication and Session Management](Document/0x05f-Testing-Authentication.md) -- [Daniel Ramirez](https://github.com/ram7rez) - *ramirez*
- [Testing Network Communication](Document/0x05g-Testing-Network-Communication.md) -- [Pawel Rzepa](https://github.com/th3g1itch) - *xep624*
- [Testing Platform Interaction](Document/0x05h-Testing-Platform-Interaction.md) -- [Sven Schleier](https://github.com/sushi2k) - *sushi2k*
- [Testing Code Quality and Build Settings](Document/0x05i-Testing-Code-Quality-and-Build-Settings.md) -- [Abdessamad Temmar](https://github.com/TmmmmmR) - *temmar*
- [Testing Resiliency Against Reverse Engineering](Document/0x05j-Testing-Resiliency-Against-Reverse-Engineering.md) -- [Bernhard Mueller](https://github.com/b-mueller) - *bernhardm*

### iOS Testing Guide

- [Platform Overview](Document/0x06a-Platform-Overview.md) -- Help Wanted
- [Basic Security Testing on iOS](Document/0x06b-Basic-Security-Testing.md) -- [Sven Schleier](https://github.com/sushi2k) - *sushi2k*
- [Tampering and Reverse Engineering on iOS](Document/0x06c-Reverse-Engineering-and-Tampering.md) -- [Bernhard Mueller](https://github.com/b-mueller) - *bernhardm*
- [Testing Data Storage](Document/0x06d-Testing-Data-Storage.md) -- [Gerhard Wagner](https://github.com/thec00n) - *bernhardm*
- [Testing Cryptography](Document/0x06e-Testing-Cryptography.md) --  [Alexander Anthuk](https://github.com/c0rdis) - *alex*, [Gerhard Wagner](https://github.com/thec00n) - *gerhard*
- [Testing Authentication and Session Management](Document/0x06f-Testing-Authentication-and-Session-Management.md) --  [Daniel Ramirez](https://github.com/ram7rez) - *ramirez*
- [Testing Network Communication](Document/0x06g-Testing-Network-Communication.md) -- [Pawel Rzepa](https://github.com/th3g1itch)
- [Testing Platform Interaction](Document/0x06h-Testing-Platform-Interaction.md) -- [Sven Schleier](https://github.com/sushi2k) - *sushi2k*
- [Testing Code Quality and Build Settings](Document/0x06i-Testing-Code-Quality-and-Build-Settings.md) -- [Abdessamad Temmar](https://github.com/TmmmmmR) - *temmar*
- [Testing Resiliency Against Reverse Engineering](Document/0x06j-Testing-Resiliency-Against-Reverse-Engineering.md) -- [Bernhard Mueller](https://github.com/b-mueller) - *bernhardm*

### Appendix

* [Security Testing in the Application Development Lifecycle](Document/0x07-Security-Testing-SDLC.md) -- [Romuald Szkudlarek](https://github.com/romualdszkudlarek) - *romualds*, [Stefan Streichsbier](https://github.com/streichsbaer)- *stefan*
* [Testing Tools](Document/0x08-Testing-Tools.md) -- [Prathan Phongthiproek](https://github.com/tanprathan/) - *tan_prathan*
* [Suggested Reading](Document/0x09-Suggested-Reading.md) - N/A


