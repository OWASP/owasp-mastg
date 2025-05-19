---
title: Dependencies with Known Vulnerabilities
id: MASWE-0076
alias: known-vuln-deps
platform: [android, ios]
profiles: [L1, L2]
mappings:
  masvs-v1: [MSTG-CODE-5]
  masvs-v2: [MASVS-CODE-3]
status: new
refs:
- https://developer.android.com/privacy-and-security/risks/insecure-library
---

## Overview

External or third-party libraries, SDK's or frameworks used by the app that contain security flaws that are publicly documented, usually through CVE's, are called "Dependencies with Known Vulnerabilities".

## Impact

Using dependencies with known vulnerabilities in mobile apps can result in various security risks, including but not limited to:

- **Data Exposure**: Known vulnerabilities in dependencies can be exploited by attackers to gain unauthorized access to sensitive user data or app functionality. This can lead to data breaches, exposing private information like user credentials or personal data, which can have legal and financial consequences for the app owner and undermine user trust.
- **Compromise of System Integrity and Functionality**: Vulnerabilities in dependencies may allow attackers to compromise the app’s overall integrity, potentially introducing malicious behavior such as unauthorized code execution or privilege escalation. This can lead to account take-over or lead to app downtime.
- **Non-Compliance**: Using outdated or vulnerable dependencies can result in non-compliance with security standards and regulations. This can expose businesses to regulatory penalties and legal liabilities, especially in industries handling sensitive data like healthcare or finance.

## Modes of Introduction

Mobile apps rely heavily on dependencies. This can be "closed-source" dependencies through vendor products, or "open-source" dependencies that are maintained by the community.

Dependencies can be implemented manually by adding them into the project and linking them, but are usually added through dependency managers that take care of the integration into the project's files.

## Mitigations

- **Keep Dependencies Updated**: Regularly update dependencies to their latest secure versions to ensure that any known vulnerabilities are patched.
- **Regular Dependency Audits:**: Continuously scan and audit third-party libraries for vulnerabilities using Software Composition Analysis (SCA) tools in the CI/CD pipeline, like @MASTG-TOOL-0131 or @MASTG-TOOL-0132.
- **Software Bill of Material (SBOM)**: Create a SBOM and manage the dependencies by using tools like @MASTG-TOOL-0134 and @MASTG-TOOL-0132.
- **Remove Unused Dependencies**: Regularly review and remove any unused or unnecessary libraries to reduce the app’s attack surface.
