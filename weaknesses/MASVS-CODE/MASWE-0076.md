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

"Dependencies with Known Vulnerabilities" are external or third-party libraries, SDKs, or frameworks used by the app that contain publicly documented security flaws, usually through CVEs.

## Impact

Using dependencies with known vulnerabilities in mobile apps can result in various security risks, including but not limited to:

- **Data Exposure**: Attackers can exploit known vulnerabilities in dependencies to gain unauthorized access to sensitive user data or app functionality. This can lead to data breaches that expose private information, such as user credentials or personal data. Such breaches can have legal and financial consequences for the app owner and undermine user trust.
- **Compromise of System Integrity and Functionality**: Vulnerabilities in dependencies may allow attackers to compromise the app's overall integrity, potentially introducing malicious behavior such as unauthorized code execution or privilege escalation. This can lead to account takeover or app downtime.
- **Non-Compliance**: Using outdated or vulnerable dependencies may result in noncompliance with security standards and regulations. This can expose businesses to regulatory penalties and legal liabilities, especially those in industries that handle sensitive data, such as healthcare or finance.

## Modes of Introduction

Mobile apps rely heavily on dependencies. These dependencies can be "closed-source" through vendor products or "open-source" and maintained by the community.

Dependencies can be implemented manually by adding them into the project and linking them, but they are usually added through dependency managers, which handle the integration into the project's files.

## Mitigations

- **Keep Dependencies Updated**: Regularly update dependencies to their latest secure versions to ensure that any known vulnerabilities are patched.
- **Regular Dependency Audits:**: Continuously scan and audit third-party libraries for vulnerabilities using Software Composition Analysis (SCA) tools in the CI/CD pipeline, like @MASTG-TOOL-0131 or @MASTG-TOOL-0132.
- **Software Bill of Material (SBOM)**: Create a SBOM and manage the dependencies by using tools like @MASTG-TOOL-0134 and @MASTG-TOOL-0132.
- **Remove Unused Dependencies**: Regularly review and remove any unused or unnecessary libraries to reduce the app's attack surface.
