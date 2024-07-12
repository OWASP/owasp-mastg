---
title: "MASTG Refactor Part 2 - Techniques, Tools & Reference Apps"
date: 2023-09-29
authors: [carlos, sven]
---

We are thrilled to announce the second phase of the MASTG (Mobile Application Security Testing Guide) refactor. These changes aim to enhance the usability and accessibility of the MASTG.

The primary focus of this new refactor is the reorganization of the MASTG content into different components, each housed in its dedicated section/folder and existing now as individual pages in our website (markdown files with metadata/frontmatter in GitHub):

<center>
<img style="width: 80%; border-radius: 5px" src="/assets/news/mastg_refactor_2.png"/>
</center>

<!-- more -->

- **Tests**:
    - Website: [Tests](https://mas.owasp.org/MASTG/tests/) section.
    - GitHub: [`tests/` folder](https://github.com/OWASP/owasp-mastg/tree/master/tests).
    - Identified by IDs in the format `MASTG-TEST-XXXX`.
    - Includes all tests originally in:
        - 0x05d/0x06d-Testing-Data-Storage.md
        - 0x05e/0x06e-Testing-Cryptography.md
        - 0x05f/0x06f-Testing-Local-Authentication.md
        - 0x05g/0x06g-Testing-Network-Communication.md
        - 0x05h/0x06h-Testing-Platform-Interaction.md
        - 0x05i/0x06i-Testing-Code-Quality-and-Build-Settings.md
        - 0x05j/0x06j-Testing-Resiliency-Against-Reverse-Engineering.md
    - :warning: **IMPORTANT (TODO)**: These tests are still the original MASTG v1.6.0 tests. We will progressively split them into smaller tests, the so-called "atomic tests" in MASTG v2 and assign the new MAS profiles accordingly.

- **Techniques**:
    - Website: [Techniques](https://mas.owasp.org/MASTG/techniques/) section.
    - GitHub: [`techniques/` folder](https://github.com/OWASP/owasp-mastg/tree/master/techniques).
    - Identified by IDs in the format `MASTG-TECH-XXXX`.
    - Includes all techniques originally in:
        - 0x05b/0x06b-Basic-Security_Testing.md
        - 0x05c/0x06c-Reverse-Engineering-and-Tampering.md

- **Tools**:
    - Website: [Tools](https://mas.owasp.org/MASTG/tools/) section.
    - GitHub: [`tools/` folder](https://github.com/OWASP/owasp-mastg/tree/master/tools).
    - Identified by IDs in the format `MASTG-TOOL-XXXX`.
    - Includes all tools from:
        - 0x08a-Testing-Tools.md

- **Apps**:
    - Website: [Apps](https://mas.owasp.org/MASTG/apps/) section.
    - GitHub: [`apps/` folder](https://github.com/OWASP/owasp-mastg/tree/master/apps).
    - Identified by IDs in the format `MASTG-APP-XXXX`.
    - Includes all apps from:
        - 0x08b-Reference-Apps.md

We hope that the revamped structure enables you to navigate the MASTG more efficiently and access the information you need with ease.
