---
title: App Virtualization Environment Detection Not Implemented
id: MASWE-0098
alias: app-virtualization-detection
platform: [android]
profiles: [R]
mappings:
  masvs-v1: [MSTG-RESILIENCE-3, MSTG-RESILIENCE-4, MSTG-RESILIENCE-5, MSTG-RESILIENCE-6]
  masvs-v2: [MASVS-RESILIENCE-1, MASVS-RESILIENCE-4]
status: draft
---

## Overview

Android app virtualization software is a potential vector for dynamic analysis and application tampering. Such software can partially or fully virtualize the Android system, enabling target applications to run in a controlled environment. It bypasses the Android security model by creating a more permissive environment that other threat tools can exploit, often without requiring the device to be rooted.

Malware can exploit Android virtualization software by encapsulating legitimate applications within a virtualized environment, creating seemingly identical user experience. This kind of virtualization allows malicious actors to inject code that bypasses security measures, such as anti-tampering protections, enabling malware to execute fraudulent activities.

Dynamic instrumentation tools, like [GameGuardian](https://gameguardian.net/forum/topic/20322-gameguardian-work-without-root/), can leverage Android virtualization software to operate on non-rooted devices.

## Impact

Maliciously used Android virtualization software can lead to a variety of security issues, including but not limited to:

- **Unauthorized reading of application private data**: Malware utilizing Android virtualization software to virtualize a target application can access its private data. This can lead to exposure of sensitive user information, such as login credentials, financial data, and personal messages, compromising user privacy and security.
- **Unauthorized alteration of application private data**: By injecting malicious code through virtualization, malware can modify private data within an application. This alteration can result in unauthorized transactions, changes to user settings, or tampering with the application's functionality, potentially causing financial loss or operational disruptions.
- **Unauthorized escalation of privileges or identity theft**: Virtualization software can create a more permissive environment, enabling the execution of other malicious tools that would normally require root permissions.
- **Circumventing security mechanisms**: Virtualizers can dynamically tamper with the application's memory without altering the application's integrity. This allows malicious code to bypass certain anti-tampering security measures.

## Modes of Introduction

Virtualization software introduces an additional layer between an application and its underlying operating environment, fundamentally altering how applications interact with system resources. This extra layer creates a more permissive environment, which can have significant implications for both legitimate use and potential threats.

In a virtualized environment, the software effectively isolates the application from the actual operating system and hardware, allowing the virtualization software to monitor and control any interactions with the system. This is normally not possible on a non-rooted system.

For example, by emulating or partially recreating the Android system within an application sandbox, virtualization software can enable behavior that might otherwise be restricted or monitored. This allows applications to execute in a way that sidesteps traditional security constraints, making it easier to analyze, manipulate, or modify their behavior.

## Mitigations

To mitigate the risks associated with Android virtualization software, developers should:

- **Verify platform integrity**: Some Android virtualization software either emulates the entire Android operating system or partially recreates it within an application sandbox. Checking for anomalies in the application process sandbox can help detect the presence of such virtualization software.
- **Verify application integrity**: Certain types of Android virtualization software load the target application into their own process. Verifying application and process metadata can help detect both the presence of virtualization software and any potential tampering.
- **Check the presence of malicious tools**: Android virtualization software is often used to run malicious tools on a device without root access. For example, [VirtualXposed](https://github.com/android-hacker/VirtualXposed) utilizes the [Xposed](https://github.com/rovo89/Xposed) based hooking framework. Monitoring for such tools can provide indirect indications of virtualization software, especially in the absence of root access.
