# Testing Data Storage

## Overview

[Describe what this chapter is about.]

## Test Cases

### OMTG-DATAST-001-1: Test for system credentials storage features
Mobile operating systems offer different native functions to store sensitive information like credentials and keys encrypted within the device. In case credentials or keys needs to be stored, several best practices available on the OS level should be applied to make it harder for attackers to retrieve these information.

The following tasks should be done when analysing an App:
* Identify keys and passwords in the App, e.g. entered by the users, sent back by the endpoint, shipped within the App and how this sensitive data is processed locally.
* Decide with the developers if this sensitive stored information locally is needed and if not, how it can be removed or moved to the server (endpoint).

#### Detailed Guides

- [OMTG-DATAST-001-1 Android](0x00a_OMTG-DATAST_Android.md#OMTG-DATAST-001-1)
- [OMTG-DATAST-001 iOS](0x00b_OMTG-DATAST_iOS.md#OMTG-DATAST-001)

#### References

##### OWASP MASVS: V2.1: Data Storage and Privacy requirements:
* Verify that system credential storage facilities are used appropriately to store sensitive data, such as user credentials or cryptographic keys.

##### OWASP Mobile Top 10
* M1 - Improper Platform Usage
* M2 - Insecure Data Storage

##### CWE
* CWE-311 - Missing Encryption of Sensitive Data
* CWE-312 - Cleartext Storage of Sensitive Information
* CWE-522 - Insufficiently Protected Credentials
* CWE-922 - Insecure Storage of Sensitive Information

### <a name="OMTG-DATAST-001-2"></a>OMTG-DATAST-001-2: Test for Sensitive Data Disclosure in Local Storage

The credo for saving data can be summarized quite easy: Public data should be available for everybody, but sensitive and private data needs to be protected or not stored in the first place on the device itself.  
This vulnerability can have many consequences, like disclosure of encryption keys that can be used by an attacker to decrypt information. More generally speaking an attacker might be able to identify these information to use it as a basis for other attacks like social engineering (when PII is disclosed), session hijacking (if session information or a token is disclosed) or gather information from apps that have a payment option in order to attack it.

This vulnerability occurs when sensitive data is not properly protected by an app when persistently storing it. The app might be able to store it in different places, for example locally on the device or on an external SD card.
When trying to exploit this kind of issues, consider that there might be a lot of information processed and stored in different locations. It is important to identify at the beginning what kind of information is processed by the mobile application and keyed in by the user and what might be interesting and valuable for an attacker (e.g. passwords, credit card information).

#### Detailed Guides

- [OMTG-DATAST-001-2 Android](0x00a_OMTG-DATAST_Android.md#OMTG-DATAST-001-2)
- [OMTG-DATAST-001 iOS](0x00b_OMTG-DATAST_iOS.md#OMTG-DATAST-001)

#### References

##### OWASP MASVS: V2.1: Data Storage and Privacy requirements:
* Verify that system credential storage facilities are used appropriately to store sensitive data, such as user credentials or cryptographic keys.


### OMTG-DATAST-002: Testing for Sensitive Data Disclosure in Log Files

There are many legit reasons to create log files on a mobile device, for example to keep track of crashes or errors that are stored locally when being offline and being sent to the application developer/company once online again or for usage statistics. However, logging sensitive data such as credit card number and session IDs might expose the data to attackers or malicious applications.
Log files can be created in various ways on each of the different operating systems. The following list shows the mechanisms that are available on Android:

| Android                      | iOS           |
|:-----------------------------|:-------------|
|  Log Class, .log[a-Z]        | NSLog Method |
| Logger Class                 | printf-like function |
| StrictMode                   | NSAssert-like function |
| System.out/System.err.print  | Macro |

Classification of sensitive information can vary between different industries, countries and their laws and regulations. Therefore laws and regulations need to be known that are applicable to it and to be aware of what sensitive information actually is in the context of the App.

#### Detailed Guides

- [OMTG-DATAST-002 Android](0x00a_OMTG-DATAST_Android.md#OMTG-DATAST-002)
- [OMTG-DATAST-002 iOS](0x00b_OMTG-DATAST_iOS.md#OMTG-DATAST-002)

#### References

##### OWASP Mobile Top 10
* M1 - Improper Platform Usage
* M2 - Insecure Data Storage

##### CWE
* CWE-117: Improper Output Neutralization for Logs
* CWE-532 - Information Exposure Through Log Files
* CWE-534 - Information Exposure Through Debug Log Files




### OMTG-DATAST-003: Test that no sensitive data leaks to cloud storage
[General description]

#### Detailed Guides

- [OMTG-DATAST-003 Android](0x00a_OMTG-DATAST_Android.md#OMTG-DATAST-003)
- [OMTG-DATAST-003 iOS](0x00b_OMTG-DATAST_iOS.md#OMTG-DATAST-003)

#### References

##### OWASP Mobile Top 10
* M1 - Improper Platform Usage
* M2 - Insecure Data Storage

##### CWE
- CWE: [Link to CWE issue]



### OMTG-DATAST-004: Test for sending sensitvie data to 3rd Parties
[General description]

#### Detailed Guides

- [OMTG-DATAST-004 Android](0x00a_OMTG-DATAST_Android.md#OMTG-DATAST-004)
- [OMTG-DATAST-004 iOS](0x00b_OMTG-DATAST_iOS.md#OMTG-DATAST-004)

#### References

##### OWASP Mobile Top 10
* M1 - Improper Platform Usage
* M2 - Insecure Data Storage

##### CWE
- CWE: [Link to CWE issue]



### OMTG-DATAST-005: Test that keyboard cache is disabled for sensitive data
[General description]

#### Detailed Guides

- [OMTG-DATAST-005 Android](0x00a_OMTG-DATAST_Android.md#OMTG-DATAST-005)
- [OMTG-DATAST-005 iOS](0x00b_OMTG-DATAST_iOS.md#OMTG-DATAST-005)

#### References

##### OWASP Mobile Top 10
* M1 - Improper Platform Usage
* M2 - Insecure Data Storage

##### CWE
- CWE: [Link to CWE issue]



### OMTG-DATAST-006: Test that clipboard is deactivated for sensitive input fields
[General description]

#### Detailed Guides

- [OMTG-DATAST-006 Android](0x00a_OMTG-DATAST_Android.md#OMTG-DATAST-006)
- [OMTG-DATAST-006 iOS](0x00b_OMTG-DATAST_iOS.md#OMTG-DATAST-006)

#### References

##### OWASP Mobile Top 10
* M1 - Improper Platform Usage
* M2 - Insecure Data Storage

##### CWE
- CWE: [Link to CWE issue]



### OMTG-DATAST-007: Test that no sensitive data is exposed via IPC mechanisms
[General description]

#### Detailed Guides

- [OMTG-DATAST-007 Android](0x00a_OMTG-DATAST_Android.md#OMTG-DATAST-007)
- [OMTG-DATAST-007 iOS](0x00b_OMTG-DATAST_iOS.md#OMTG-DATAST-007)

#### References

##### OWASP Mobile Top 10
* M1 - Improper Platform Usage
* M2 - Insecure Data Storage

##### CWE
- CWE: [Link to CWE issue]





### OMTG-DATAST-009: Test for Sensitive Data in Backups
[General description]

#### Detailed Guides

- [OMTG-DATAST-009 Android](0x00a_OMTG-DATAST_Android.md#OMTG-DATAST-009)
- [OMTG-DATAST-009 iOS](0x00b_OMTG-DATAST_iOS.md#OMTG-DATAST-009)

#### References

- OWASP MASVS: V2-1: "Verify that system credential storage facilities are used appropriately to store sensitive data, such as user credentials or cryptographic keys."
- CWE: [Link to CWE issue]


### OMTG-DATAST-010: Test that no sensitive data leaks when backgrounded
[General description]

#### Detailed Guides

- [OMTG-DATAST-010 Android](0x00a_OMTG-DATAST_Android.md#OMTG-DATAST-010)
- [OMTG-DATAST-010 iOS](0x00b_OMTG-DATAST_iOS.md#OMTG-DATAST-010)

#### References

##### OWASP Mobile Top 10
* M1 - Improper Platform Usage
* M2 - Insecure Data Storage

##### CWE
- CWE: [Link to CWE issue]



### OMTG-DATAST-011: Test for Sensitive Data Disclosure in Process Memory
[General description]

#### Detailed Guides

- [OMTG-DATAST-011 Android](0x00a_OMTG-DATAST_Android.md#OMTG-DATAST-011)
- [OMTG-DATAST-011 iOS](0x00b_OMTG-DATAST_iOS.md#OMTG-DATAST-011)

#### References

##### OWASP Mobile Top 10
* M1 - Improper Platform Usage
* M2 - Insecure Data Storage

##### CWE
- CWE: [Link to CWE issue]



### OMTG-DATAST-012: Test support of Hardware-Backed Keystore
[General description]

#### Detailed Guides

- [OMTG-DATAST-012 Android](0x00a_OMTG-DATAST_Android.md#OMTG-DATAST-012)
- [OMTG-DATAST-012 iOS](0x00b_OMTG-DATAST_iOS.md#OMTG-DATAST-012)

#### References

##### OWASP Mobile Top 10
* M1 - Improper Platform Usage
* M2 - Insecure Data Storage

##### CWE
- CWE: [Link to CWE issue]



### OMTG-DATAST-013: Test remote locking and wiping
[General description]

#### Detailed Guides

- [OMTG-DATAST-013 Android](0x00a_OMTG-DATAST_Android.md#OMTG-DATAST-013)
- [OMTG-DATAST-013 iOS](0x00b_OMTG-DATAST_iOS.md#OMTG-DATAST-013)

#### References

##### OWASP Mobile Top 10
* M1 - Improper Platform Usage
* M2 - Insecure Data Storage

##### CWE
- CWE: [Link to CWE issue]

