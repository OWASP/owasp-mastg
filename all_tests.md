# All Test Cases in the OWASP Mobile Security Testing Guide

| ID | Name | Howto | MASVS |
| --- | --- | --- | --- | --- | --- |
| OMTG-DATAST-001 | Test local data storage | Android iOS | [Data Storage](Document/0x07-V2-Data_Storage_and_Privacy_requirements.md) - V2.1 |
| OMTG-DATAST-002 | Test for sensitive data in logs | [Android](Document/Testcases/0x01a_OMTG-DATAST_Android.md#OMTG-DATAST-002) [iOS](Document/Testcases/0x02a_OMTG-DATAST_iOS.md#OMTG-DATAST-002) | [Data Storage](Document/Testcases/0x02a_OMTG-DATAST_iOS.md#OMTG-DATAST-002) - V2.2 |
| OMTG-DATAST-003 | Test for sensitive data in cloud storage | [Android](Document/Testcases/0x01a_OMTG-DATAST_Android.md#OMTG-DATAST-003) iOS | [Data Storage](https://github.com/OWASP/owasp-masvs/blob/master/Document/0x07-V2-Data_Storage_and_Privacy_requirements.md) - V2.3 |
| OMTG-DATAST-004 | Verify that no sensitive data is sent to third parties | [Android](Document/Testcases/0x01a_OMTG-DATAST_Android.md#OMTG-DATAST-004) iOS |[Data Storage](https://github.com/OWASP/owasp-masvs/blob/master/Document/0x07-V2-Data_Storage_and_Privacy_requirements.md) - V2.4 |
| OMTG-DATAST-005 | Test for sensitive data in the keyboard cache | [Android](Document/Testcases/0x01a_OMTG-DATAST_Android.md#OMTG-DATAST-005) [iOS](Document/Testcases/0x02a_OMTG-DATAST_iOS.md#OMTG-DATAST-005) | [Data Storage](https://github.com/OWASP/owasp-masvs/blob/master/Document/0x07-V2-Data_Storage_and_Privacy_requirements.md) - V2.5 |
| OMTG-DATAST-006 | Test for sensitive Data in the clipboard  |  Android [iOS](Document/Testcases/0x02a_OMTG-DATAST_iOS.md#OMTG-DATAST-006) | [Data Storage](https://github.com/OWASP/owasp-masvs/blob/master/Document/0x07-V2-Data_Storage_and_Privacy_requirements.md) - V2.6 |
| OMTG-DATAST-007 | Test IPC mechanisms for sensitive data exposure | [Android](Document/Testcases/0x01a_OMTG-DATAST_Android.md#OMTG-DATAST-007) iOS| [Data Storage](https://github.com/OWASP/owasp-masvs/blob/master/Document/0x07-V2-Data_Storage_and_Privacy_requirements.md) - V2.7 |
| OMTG-DATAST-008 | Test for sensitive data in screenshots |  [Android](Document/Testcases/0x01a_OMTG-DATAST_Android.md#OMTG-DATAST-008) iOS | [Data Storage](https://github.com/OWASP/owasp-masvs/blob/master/Document/0x07-V2-Data_Storage_and_Privacy_requirements.md) - V2.8 |
| OMTG-DATAST-009 | Test for sensitive data in backups | [Android](Document/Testcases/0x01a_OMTG-DATAST_Android.md#OMTG-DATAST-009) iOS | [Data Storage](https://github.com/OWASP/owasp-masvs/blob/master/Document/0x07-V2-Data_Storage_and_Privacy_requirements.md) - V2.9 |
| OMTG-DATAST-010 | Verify that memory is cleared when the app is backgrounded | [Android](Document/Testcases/0x01a_OMTG-DATAST_Android.md#OMTG-DATAST-010) [iOS](Document/Testcases/0x02a_OMTG-DATAST_iOS.md#OMTG-DATAST-010) | [Data Storage](https://github.com/OWASP/owasp-masvs/blob/master/Document/0x07-V2-Data_Storage_and_Privacy_requirements.md) - V2.10 |
| OMTG-DATAST-011 | Test for sensitive data in memory | [Android](Document/Testcases/0x01a_OMTG-DATAST_Android.md#OMTG-DATAST-011) iOS| [Data Storage](https://github.com/OWASP/owasp-masvs/blob/master/Document/0x07-V2-Data_Storage_and_Privacy_requirements.md) - V2.11 |
| OMTG-DATAST-012 | Test remote locking and wiping |  Android iOS | [Data Storage](https://github.com/OWASP/owasp-masvs/blob/master/Document/0x07-V2-Data_Storage_and_Privacy_requirements.md) - V2.12 |
| OMTG-DATAST-013 | Verify that a device-access-security policy is Enforced |  Android iOS | Data Storage - V2.13 |
| OMTG-CRYPTO-001 | Test cryptographic modules |  Android iOS | [Cryptography](https://github.com/OWASP/owasp-masvs/blob/master/Document/0x08-V3-Cryptography_Verification_Requirements.md) - V3.1 - V3.5 |
| OMTG-CRYPTO-002 | Verify that all random values are generated using a sufficiently secure random number generator.  | Android iOS| [Cryptography](https://github.com/OWASP/owasp-masvs/blob/master/Document/0x08-V3-Cryptography_Verification_Requirements.md) - V3.6 |
| OMTG-CRYPTO-003 | Verify that all keys and passwords are changeable, and are generated or replaced at installation time. | Android iOS | [Cryptography](https://github.com/OWASP/owasp-masvs/blob/master/Document/0x08-V3-Cryptography_Verification_Requirements.md) - V3.7 |
| OMTG-AUTH-001 | Test user authentication |  Android iOS | Authentication - V3.1 |
| OMTG-AUTH-002 | Verify that session management is implemented correctly |  Android iOS | Authentication - V3.2 |
| OMTG-AUTH-003 | Test the password policy |  Android iOS | Authentication  - V3.3 |
| OMTG-AUTH-004 | Verify that sessions are terminated upon login |  Android iOS | Authentication  - V3.4 |
| OMTG-AUTH-005 | Verify that sessions are terminated after a predefined period of inactivity | Android iOS | Authentication - V3.5 |
| OMTG-AUTH-006 | Test for user account lock or back-off in response to excessive login attempts |  Android iOS | Authentication  - V3.6|
| OMTG-AUTH-007 | Test biometric authentication |  Android iOS | Authentication  - V.3.7 |
| OMTG-AUTH-008 | Test 2-factor authentication |  Android iOS | Authentication  - V.3.8 |
| OMTG-AUTH-009 | Test step-up authentication |  Android iOS | Authentication - V.3.9 |
| OMTG-AUTH-010 | Test for session hijacking |  Android iOS | Authentication - V.3.10 |
| OMTG-AUTH-011 | Test user device management |  Android iOS | Authentication - V.3.11 |
| OMTG-NET-001 | Test network data encryption |  Android iOS | [Network](https://github.com/OWASP/owasp-masvs/blob/master/Document/0x10-V5_Network_communication_requirements.md) - V5.1 |
| OMTG-NET-002 | Test X.509 certificate verification |  Android iOS | [Network](https://github.com/OWASP/owasp-masvs/blob/master/Document/0x10-V5_Network_communication_requirements.md) - V3.2 |
| OMTG-NET-003 | Test SSL pinning |  Android iOS | [Network](https://github.com/OWASP/owasp-masvs/blob/master/Document/0x10-V5_Network_communication_requirements.md)  - V3.3 |
| OMTG-NET-004 | Verify that perfect forward secrecy is enabled |  Android iOS | [Network](https://github.com/OWASP/owasp-masvs/blob/master/Document/0x10-V5_Network_communication_requirements.md)  - V3.4 |
| OMTG-NET-005 | Test for insecure communication channels | Android iOS | [Network](https://github.com/OWASP/owasp-masvs/blob/master/Document/0x10-V5_Network_communication_requirements.md) - V3.5 |
| OMTG-NET-006 | Test PKI mutual authentication |  Android iOS | [Network](https://github.com/OWASP/owasp-masvs/blob/master/Document/0x10-V5_Network_communication_requirements.md)  - V3.6|
| OMTG-ENV-001 | Test app permissions |  Android iOS | Authentication - [Environment](https://github.com/OWASP/owasp-masvs/blob/master/Document/0x11-V6_Interaction_with_the_environment.md) V6.1 |
| OMTG-ENV-002 | Test validation of input from external sources |  Android iOS | Authentication - [Environment](https://github.com/OWASP/owasp-masvs/blob/master/Document/0x11-V6_Interaction_with_the_environment.md) V6.1  |
| OMTG-ENV-003 | Test validation of user input |  Android iOS | Authentication  - [Environment](https://github.com/OWASP/owasp-masvs/blob/master/Document/0x11-V6_Interaction_with_the_environment.md) V6.1  |
| OMTG-ENV-004 | Test custom URL schemes |  Android iOS | Authentication  - [Environment](https://github.com/OWASP/owasp-masvs/blob/master/Document/0x11-V6_Interaction_with_the_environment.md) V6.1  |
| OMTG-ENV-005 | Test IPC functionality | Android iOS | Authentication - [Environment](https://github.com/OWASP/owasp-masvs/blob/master/Document/0x11-V6_Interaction_with_the_environment.md) V6.1  |
| OMTG-ENV-006 | Test WebViews |  Android iOS | Authentication  - [Environment](https://github.com/OWASP/owasp-masvs/blob/master/Document/0x11-V6_Interaction_with_the_environment.md) V6.6 - v6.10 |
| OMTG-ENV-011 | Verify that the app forces updates of outdated system components |  Android iOS | [Environment](https://github.com/OWASP/owasp-masvs/blob/master/Document/0x11-V6_Interaction_with_the_environment.md)  |
| OMTG-ENV-012 | Verify that the app checks its installation source |  Android iOS | [Environment](https://github.com/OWASP/owasp-masvs/blob/master/Document/0x11-V6_Interaction_with_the_environment.md) V6.1  |
| OMTG-ENV-013 | Test basic root / jailbreak detection |  Android iOS | [Environment](https://github.com/OWASP/owasp-masvs/blob/master/Document/0x11-V6_Interaction_with_the_environment.md) V6.1  |

