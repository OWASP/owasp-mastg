---
title: Insecure Machine-to-Machine Communication
id: MASWE-0048
alias: insecure-m2m
platform: [android, ios]
profiles: [L1, L2]
mappings:
  masvs-v1: [MSTG-NETWORK-1]
  masvs-v2: [MASVS-NETWORK-1]
  cwe: [311, 319]
  android-risks:
    - https://developer.android.com/privacy-and-security/risks/insecure-machine-to-machine
draft:
  description: Android applications often use technologies like Bluetooth, NFC, and USB for data transfer and device interaction. Developers must use these APIs carefully to prevent data exposure and remote device takeover by attackers.
  topics:
    - Bluetooth
    - BLE
    - NFC
    - USB
    - Wi-Fi P2P
status: placeholder
---
