# Testing Resiliency Against Reverse Engineering

## Overview

This chapter covers defense-in-depth measures that are recommended for apps that process, or give access to, sensitive data or functionality. Lack of any of these controls does not cause a vulnerability - instead, they are meant to increase the app's resiliency against reverse engineering, making it more difficult for adversaries to gain an understanding of the app's internals or extract data from the app.

## Test Cases

### OMTG-RARE-001: Test the Custom Keyboard

#### Detailed Guides

- [OMTG-RARE-001 Android](0x06a_OMTG-RARE_Android.md#OMTG-RARE-001)
- [OMTG-RARE-001 iOS](0x06b_OMTG-RARE_iOS.md#OMTG-RARE-001)

#### References

- OWASP MASVS: V9-1: "The app provides a custom keyboard whenever sensitive data is entered."
- CWE: N/A

### OMTG-RARE-002: Test for Sensitive Data in UI Components

#### Detailed Guides

- [OMTG-RARE-002 Android](0x06a_OMTG-RARE_Android.md#OMTG-RARE-002)
- [OMTG-RARE-002 iOS](0x06b_OMTG-RARE_iOS.md#OMTG-RARE-002)

#### References

- OWASP MASVS: V9-2: "Custom UI components are used to display sensitive data. The UI components should not rely on immutable data structures."
- CWE: N/A

### OMTG-RARE-003: Test Advanced Jailbreak / Root Detection

#### Detailed Guides

- [OMTG-RARE-003 Android](0x06a_OMTG-RARE_Android.md#OMTG-RARE-003)
- [OMTG-RARE-003 iOS](0x06b_OMTG-RARE_iOS.md#OMTG-RARE-003)

#### References

- OWASP MASVS : V9.3: "Verify that the app implements two or more functionally independent methods of root detection and responds to the presence of a rooted device either by alerting the user or terminating the app."
- CWE : N/A

### OMTG-RARE-004: Test Advanced Debugging Defenses

#### Detailed Guides

- [OMTG-RARE-004 Android](0x06a_OMTG-RARE_Android.md#OMTG-RARE-004)
- [OMTG-RARE-004 iOS](0x06b_OMTG-RARE_iOS.md#OMTG-RARE-004)

#### References

- OWASP MASVS : V9.4: "The app implements multiple functionally independent debugging defenses that, in context of the overall protection scheme, force adversaries to invest significant manual effort to enable debugging. All available debugging protocols must be covered (e.g. JDWP and native)."
- CWE : N/A

### OMTG-RARE-005: Test File Tampering Detection

#### Detailed Guides

- [OMTG-RARE-005 Android](0x06a_OMTG-RARE_Android.md#OMTG-RARE-005)
- [OMTG-RARE-005 iOS](0x06b_OMTG-RARE_iOS.md#OMTG-RARE-005)

#### References

- OWASP MASVS : V9.5: "Verify that the app detects and responds to tampering with executable files and critical data."
- CWE : N/A

### OMTG-RARE-006: Test Detection of Reverse Engineering Tools

#### Detailed Guides

- [OMTG-RARE-006 Android](0x06a_OMTG-RARE_Android.md#OMTG-RARE-006)
- [OMTG-RARE-006 iOS](0x06b_OMTG-RARE_iOS.md#OMTG-RARE-006)

#### References

- OWASP MASVS : V9.6: "The app detects the presence of widely used reverse engineering tools, such as code injection tools, hooking frameworks and debugging servers."
- CWE : N/A

### OMTG-RARE-007: Test Basic Emulator Detection

#### Detailed Guides

- [OMTG-RARE-007 Android](0x06a_OMTG-RARE_Android.md#OMTG-RARE-007)
- [OMTG-RARE-007 iOS](0x06b_OMTG-RARE_iOS.md#OMTG-RARE-007)

#### References

- OWASP MASVS : V9.7: "The app detects, and responds to, being run in an emulator using any method."
- CWE : N/A

### OMTG-RARE-008: Test Memory Tampering Detection

#### Detailed Guides

- [OMTG-RARE-008 Android](0x06a_OMTG-RARE_Android.md#OMTG-RARE-008)
- [OMTG-RARE-008 iOS](0x06b_OMTG-RARE_iOS.md#OMTG-RARE-008)

#### References

- OWASP MASVS : V9.8: "The app detects, and responds to, modifications of process memory, including relocation table patches and injected code."
- CWE : N/A

### OMTG-RARE-009: Test Variability of Tampering Responses

#### Detailed Guides

- [OMTG-RARE-009 Android](0x06a_OMTG-RARE_Android.md#OMTG-RARE-009)
- [OMTG-RARE-009 iOS](0x06b_OMTG-RARE_iOS.md#OMTG-RARE-009)

#### References

- OWASP MASVS : V9.9: "The app implements multiple different responses to tampering, debugging and emulation, including stealthy responses that don't simply terminate the app.."
- CWE : N/A

### OMTG-RARE-010: Test Binary Encryption

#### Detailed Guides

- [OMTG-RARE-010 Android](0x06a_OMTG-RARE_Android.md#OMTG-RARE-010)
- [OMTG-RARE-010 iOS](0x06b_OMTG-RARE_iOS.md#OMTG-RARE-010)

#### References

- OWASP MASVS : V9.10: "All executable files and libraries belonging to the app are either encrypted on the file level and/or important code and data segments inside the executables are encrypted or packed. Trivial static analysis should not reveal important code or data."
- CWE : N/A

### OMTG-RARE-014: Test Device Binding

#### Detailed Guides

- [OMTG-RARE-011 Android](0x06a_OMTG-RARE_Android.md#OMTG-RARE-011)
- [OMTG-RARE-011 iOS](0x06b_OMTG-RARE_iOS.md#OMTG-RARE-011)

#### References

- OWASP MASVS : V9.11: "Obfuscating transformations and functional defenses are interdependent and well-integrated throughout the app."
- CWE : N/A

(... TODO ...)
