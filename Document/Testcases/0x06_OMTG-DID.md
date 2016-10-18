# Testing Defense-in-Depth

## Overview

[Describe what this chapter is about.]

## Test Cases

### OMTG-DID-001: Testing SSL Pinning
Certificate pinning allows to hard-code in the client the certificate that is known to be used by the server. This technique is used to reduce the threat of a rogue CA and CA compromise. Pinning the server’s certificate take the CA out of games. Mobile applications that implements certificate pinning only have to connect to a limited numbers of server, so a small list of trusted CA can be hard-coded in the application.

#### Detailed Guides

- [OMTG-DID-001 Android](0x06a_OMTG-DID_Android.md#OMTG-DID-001)
- [OMTG-DID-001 iOS](0x06b_OMTG-DID_iOS.md#OMTG-DID-001)

#### References

- OWASP MASVS : [Link to MASVS]
- CWE : [Link to CWE issue]

### OMTG-DID-002: Testing for Jailbreak / Root Detection
Modern smartphone operating systems implement containerization so that each app is restricted to its own sandbox. A regular app cannot access files outside its dedicated data directories, and access to system APIs is restricted via app privileges. As a result, an app’s sensitive data as well as the integrity of the OS is guaranteed under normal conditions. However, when an adversary gains root access to the mobile operating system, the default protections can be bypassed completely.

The risk of malicious code running as root is higher on rooted or jailbroken devices, as some of the default integrity checks are disabled. Developers of apps that handle highly sensitive data (e.g. banking) should therefore consider implementing checks that prevent the app from running under these conditions.


#### Detailed Guides

- [OMTG-DID-002 Android](0x06a_OMTG-DID_Android.md#OMTG-DID-002)
- [OMTG-DID-002 iOS](0x06b_OMTG-DID_iOS.md#OMTG-DID-002)

#### References

- OWASP MASVS : [Link to MASVS]
- CWE : [Link to CWE issue]

### OMTG-DID-003: Testing for Secure Compiler Flags
Compilers such as CLANG and GCC support hardening options that add additional runtime security features and checks to the generated executables. While these hardening features don’t fix broken code, they do make exploitation of bugs such as buffer overflows more difficult, and should be activated as a defense-in-depth measure.

#### Detailed Guides

- [OMTG-DID-003 Android](0x06a_OMTG-DID_Android.md#OMTG-DID-003)
- [OMTG-DID-003 iOS](0x06b_OMTG-DID_iOS.md#OMTG-DID-003)

#### References

- OWASP MASVS : [Link to MASVS]
- CWE : [Link to CWE issue]

### OMTG-DID-004: Testing the Custom Keyboard
[Description]


#### Detailed Guides

- [OMTG-DID-004 Android](0x06a_OMTG-DID_Android.md#OMTG-DID-004)
- [OMTG-DID-004 iOS](0x06b_OMTG-DID_iOS.md#OMTG-DID-004)

#### References

- OWASP MASVS : [Link to MASVS]
- CWE : [Link to CWE issue]
