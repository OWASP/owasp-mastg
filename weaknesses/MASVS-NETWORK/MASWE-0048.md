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
status: released
---

## Overview

Machine-to-Machine (M2M) communication in mobile applications encompasses various short-range wireless technologies like Bluetooth, NFC, USB, and Wi-Fi P2P. These technologies enable direct communication between devices without requiring internet connectivity. However, when implemented incorrectly, they can expose sensitive data and potentially allow unauthorized device control.

Common M2M technologies in mobile apps include:
- Bluetooth Classic and Bluetooth Low Energy (BLE)
- Near Field Communication (NFC)
- Universal Serial Bus (USB)
- Wi-Fi Peer-to-Peer (P2P)

**Limitations**: While M2M communications offer convenient device-to-device interaction, they present unique security challenges:
- Limited range does not guarantee security
- Physical proximity attacks are possible
- Multiple attack vectors across different protocols
- Complex permission models across platforms
- Varying security capabilities between protocols

## Impact

- **Unauthorized Data Access**: Attackers within range can intercept sensitive data transmitted between devices
- **Device Impersonation**: Malicious devices can masquerade as legitimate ones to establish connections
- **Man-in-the-Middle Attacks**: Attackers can intercept and modify communication between devices
- **Remote Code Execution**: Vulnerable implementations may allow attackers to execute code on connected devices
- **Privacy Breaches**: Insecure device discovery and pairing can leak user information
- **Denial of Service**: Flooding attacks can disrupt legitimate M2M communications

## Modes of Introduction

### Bluetooth/BLE Vulnerabilities
- **Insecure Pairing**: Not implementing secure pairing methods or allowing legacy pairing modes
- **Missing Authentication**: Failing to authenticate devices before data exchange
- **Weak Encryption**: Using deprecated or broken encryption methods
- **Exposed Services**: Not requiring authentication for sensitive GATT services
- **Insufficient Authorization**: Not implementing proper authorization checks for critical operations

### NFC Vulnerabilities
- **Missing Tag Validation**: Not validating NFC tag contents before processing
- **Exposed Interfaces**: Making sensitive NFC interfaces publicly accessible
- **Clear Text Data**: Transmitting sensitive data without encryption
- **Host Card Emulation Issues**: Insufficient security in HCE implementations

### USB Vulnerabilities
- **Unrestricted Access**: Not implementing proper USB access controls
- **Missing Protocol Validation**: Not validating custom USB protocols
- **Exposed Debug Interfaces**: Leaving debug interfaces accessible via USB
- **Insufficient Data Protection**: Not encrypting sensitive data transferred via USB

### Wi-Fi P2P Vulnerabilities
- **Weak Group Formation**: Not implementing secure group formation
- **Missing Channel Security**: Not securing the communication channel
- **Insufficient Access Control**: Not implementing proper access restrictions
- **Configuration Issues**: Using insecure Wi-Fi P2P configurations

## Mitigations

### General Security Measures
- Implement strong authentication for all M2M connections
- Use platform-recommended encryption for data transmission
- Validate all received data before processing
- Implement proper error handling
- Regular security testing of M2M implementations
- Maintain logs of security-relevant events

### Bluetooth/BLE Security
- Use Bluetooth 4.2 or later security features
- Implement Secure Connections Only mode
- Use strong pairing methods (e.g., Numeric Comparison)
- Implement proper service and characteristic permissions
- Use encryption for sensitive data transmission
- Regular scanning for vulnerable Bluetooth implementations

### NFC Security
- Validate all NFC tag contents
- Implement proper access controls for NFC interfaces
- Use encryption for sensitive data
- Implement secure key storage
- Regular testing of NFC implementation
- Proper error handling for malformed data

### USB Security
- Implement proper USB access controls
- Use encryption for sensitive data transfer
- Validate all USB protocols
- Disable debug interfaces in production
- Regular security testing of USB implementations
- Proper error handling for USB communications

### Wi-Fi P2P Security
- Use WPA2 or later security
- Implement secure group formation
- Use strong authentication methods
- Encrypt all sensitive data
- Regular testing of Wi-Fi P2P implementation
- Proper error handling for connection issues

## Platform-Specific Considerations

### Android
- Use the latest Android Bluetooth APIs
- Implement proper permission handling
- Use Android Keystore for key storage
- Follow Android USB security best practices
- Implement proper Wi-Fi P2P security controls

### iOS
- Use the Core Bluetooth framework securely
- Implement proper encryption using CryptoKit
- Follow Apple's USB security guidelines
- Use secure key storage in Keychain
- Implement proper access controls

## References
- [Android M2M Security Documentation](https://developer.android.com/privacy-and-security/risks/insecure-machine-to-machine)
- [iOS Security Documentation](https://support.apple.com/guide/security/welcome/web)
- [Bluetooth Security Guidelines](https://www.bluetooth.com/learn-about-bluetooth/key-attributes/bluetooth-security/)
- [NFC Forum Security Guidelines](https://nfc-forum.org/)
- [USB Security Best Practices](https://www.usb.org/documents)
