---
title: "Insecure Machine-to-Machine Communication"
id: "MASWE-0048"
alias: "insecure-m2m"
platform: 
  - android
  - ios
profiles: 
  - L1
  - L2
mappings:
  masvs-v1: 
    - MSTG-NETWORK-1
  masvs-v2: 
    - MASVS-NETWORK-1
  cwe: 
    - "311"
    - "319"
  android-risks:
    - "https://developer.android.com/privacy-and-security/risks/insecure-machine-to-machine"
status: "published"
description: "Mobile applications frequently communicate with external devices using protocols like Bluetooth, BLE, NFC, USB, and Wi-Fi P2P. If these communications are not properly secured, attackers can intercept, manipulate, or inject malicious data, leading to unauthorized access, data leaks, or even remote device control."

security_risks:
  - name: "Data Interception"
    description: "Lack of encryption in M2M communication may expose sensitive information to attackers using tools like Bluetooth sniffers or NFC skimmers."
  - name: "Man-in-the-Middle (MitM) Attacks"
    description: "Without authentication and integrity checks, attackers can modify or inject malicious data."
  - name: "Device Impersonation"
    description: "An attacker could spoof a trusted device to gain unauthorized access to sensitive data or perform unauthorized actions."
  - name: "Replay Attacks"
    description: "Attackers may capture and replay previous transmissions to trick the system into accepting malicious requests."

attack_scenarios:
  - name: "Unencrypted Bluetooth Communication"
    description: "A fitness tracker transmits health data to an app over Bluetooth Classic without encryption. Attackers can eavesdrop and extract sensitive health data."
  - name: "Insecure NFC Payment Processing"
    description: "An attacker with an NFC reader intercepts transaction details between a mobile app and an NFC payment terminal, leading to financial fraud."
  - name: "Weak Pairing Mechanism in BLE Devices"
    description: "A smart lock uses an insecure pairing method that allows attackers to brute-force the connection and gain unauthorized access."

mitigation_strategies:
  - "Always Encrypt Communications: Use strong encryption standards like AES-256 or TLS 1.2/1.3 when transmitting data."
  - "Mutual Authentication: Implement secure pairing and authentication mechanisms to prevent unauthorized device access."
  - "Integrity Checks: Use digital signatures or HMAC to verify the authenticity of messages."
  - "Replay Attack Prevention: Implement challenge-response mechanisms to prevent attackers from reusing old transmissions."
  - "Limit Device Permissions: Restrict access to only trusted devices through proper authentication and user approval flows."

references:
  - name: "OWASP MASVS-NETWORK-1"
    url: "https://mas.owasp.org/MASWE/MASVS-NETWORK/MASWE-0048/"
  - name: "Android Security: Insecure M2M Risks"
    url: "https://developer.android.com/privacy-and-security/risks/insecure-machine-to-machine"
  - name: "Bluetooth Security Recommendations"
    url: "https://www.bluetooth.com/security/"
  - name: "NIST NFC Security Guidelines"
    url: "https://csrc.nist.gov/"
---
