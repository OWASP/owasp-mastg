---
title: RASP Techniques Not Implemented
id: MASWE-0103
alias: rasp-techniques
platform: [android, ios]
profiles: [R]
mappings:
  masvs-v1: [MSTG-RESILIENCE-8]
  masvs-v2: [MASVS-RESILIENCE-4]
  cwe: [250, 829, 749]

observed_examples:
- https://nvd.nist.gov/vuln/detail/CVE-2022-33317
  
draft:
  description: e.g. Runtime Application Self-Protection, detection triggering different
    responses
  topics:
  - detection triggering different responses
status: draft

---

## Overview

RASP (Runtime Application Self-Protection) encompasses techniques such as root or jailbreak detection, unauthorised code or code execution, malware detection, system state, data logging and data flow. It provides a systematic, organised management approach to securing mobile applications in real time from potential threats.

**These techniques:**

- Ensure that the application flow remains secure and untampered at all times.
- Enable applications to detect and trigger responses to threats, such as:
    - Warning the user.
    - Killing the app.
    - Locking access to certain features.

---

Without RASP implementation, applications remain vulnerable to attacks during runtime. RASP techniques assure that the app continuously monitors both its own state and the device environment to detect threats like malware, root, or integrity issues.

**Additional benefits of implementing these techniques might include:**

- Independent decoupled protection updates.
- Remote configuration of security rules.
- Threat intelligence gathering.
- Fast security incident remediation.
- Providing data for security analysis.

---

Speed and timing of checks is also important and crucial for response times and ensuring no gaps in detection rounds, with control timing checking sensitive steps in the app. Incorporating RASP into an app ensures continuous protection from threats, ultimately minimising risk and improving overall security.

## Modes of Introduction

Mobile app security and user security can be disrupted in various scenarios, including:

- The application does not comprehensively process information and fails to account for system weaknesses or its own vulnerabilities, potentially leading to breached environment integrity.
- Direct reactions to detected threads are not properly executed or integrated into the application’s business logic.
- Security rules cannot be effectively defined based on discovered weaknesses, as this approach lacks the broader perspective needed to address all potential threats and ensure comprehensive protection.

---

## Impact

- **Loss of Control and Monitoring:** One of the key advantages of RASP is the ability to continuously control and monitor the mobile app’s state and the device environment in real-time. Without these features, the application may fail to detect or respond to unauthorised modifications, malware presence, or tampering attempts.
- **Missed Threat Intelligence:** Without continuous monitoring, security checks, and data logging, we lose a critical overview of potential threats, making it harder to identify emerging attack patterns and respond to malicious activities effectively.
- **Loss of Manageability and Updateability of Detection Techniques:** Without RASP, applications lose the ability to update security rulesets, reset policies/settings, and adjust risk scoring in older or already released apps.

---

## Mitigation

- To enhance the security of your mobile application, implement detection mechanisms that continuously monitor the app's state and device environment.
- Implement response actions for detected threats to mitigate potential risks, such as:
     Killing the app,
    - Warning the user,
    - Logging information about potential risks to the database.
- Use third-party solutions, which specialise in threat detection and real-time security monitoring (e.g. freeRASP).
  
---
