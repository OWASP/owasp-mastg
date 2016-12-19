# All Test Cases in the OWASP Mobile Security Testing Guide

| ID | Name | Links| MASVS |
| --- | --- | --- | --- | --- | --- |
| OMTG-DATAST-001 | Test Credential Storage |  General Android iOS| V2.1: System credential storage facilities are used appropriately to store sensitive data, such as user credentials or cryptographic keys. |
| OMTG-DATAST-002 | Test for Sensitive Data in Logs |  General Android iOS| V2.2: No sensitive data is written to application logs. |
| OMTG-DATAST-003 | Test for Sensitive Data in Cloud Storage |  General Android iOS| V2.3: No sensitive data is synced cloud storage. |
| OMTG-DATAST-004 | Verify that no Sensitive Data is Sent to Third Parties |  General Android iOS| V2.4: No sensitive data is sent to third parties. |
| OMTG-DATAST-005 | Test for Sensitive Data in the Keyboard Cache |  General Android iOS| V2.5: The keyboard cache is disabled on text inputs that process sensitive data. |
| OMTG-DATAST-006 | Test for Sensitive Data in the Clipboard  |  General Android iOS| V2.6: The clipboard is deactivated on text fields that may contain sensitive data. |
| OMTG-DATAST-007 | Verify that no Sensitive Data is Exposed Through IPC Mechanisms |  General Android iOS| V2.7 No sensitive data is exposed via IPC mechanisms. |
| OMTG-DATAST-008 | Test for Sensitive Data in Screenshots |  General Android iOS| V2.8: No sensitive data, such as passwords and credit card numbers, is exposed through the user interface or leaks to screenshots. |
| OMTG-DATAST-009 | Test for Sensitive Data in Backups |  General Android iOS| V2.9: No sensitive data is included in backups. |
| OMTG-DATAST-010 | Test for Sensitive Data in the Backgrounded App  |  General Android iOS| V2.10: The app removes sensitive data from views when backgrounded. |
| OMTG-DATAST-011 | Test for Sensitive Data in Memory |  General Android iOS| V2.11: The app does not hold sensitive data in memory longer than necessary, and memory is cleared explicitly after use. |
| OMTG-DATAST-012 | Test Remote Locking and Wiping |  General Android iOS| V2.12: If a remote locking mechanism exists, local storage is wiped upon locking. |
| OMTG-DATAST-013 | Verify that the Device-Access-Security Policy is Enforced |  General Android iOS| V2.13: The app enforces a minimum device-access-security policy, such as requiring the user to set a device passcode. |

