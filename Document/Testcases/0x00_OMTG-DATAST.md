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
* CWE-312 - Cleartext Storage of Sensitive Information
* CWE-522 - Insufficiently Protected Credentials



### <a name="OMTG-DATAST-001-2"></a>OMTG-DATAST-001-2: Test for Sensitive Data Disclosure in Local Storage

The credo for saving data can be summarized quite easy: Public data should be available for everybody, but sensitive and private data needs to be protected or not stored in the first place on the device itself.  
This vulnerability can have many consequences, like disclosure of encryption keys that can be used by an attacker to decrypt information. More generally speaking an attacker might be able to identify these information to use it as a basis for other attacks like social engineering (when PII is disclosed), session hijacking (if session information or a token is disclosed) or gather information from apps that have a payment option in order to attack it.

This vulnerability occurs when sensitive data is not properly protected by an app when persistently storing it. The app might be able to store it in different places, for example locally on the device or on an external SD card.
When trying to exploit this kind of issues, consider that there might be a lot of information processed and stored in different locations. It is important to identify at the beginning what kind of information is processed by the mobile application and keyed in by the user and what might be interesting and valuable for an attacker (e.g. passwords, credit card information).

#### Detailed Guides

- [OMTG-DATAST-001-2 Android](0x00a_OMTG-DATAST_Android.md#OMTG-DATAST-001-21)
- [OMTG-DATAST-001 iOS](0x00b_OMTG-DATAST_iOS.md#OMTG-DATAST-001)

#### References

* to add

### OMTG-DATAST-009: Test for Sensitive Data in Backups
[General description]

#### Detailed Guides

- [OMTG-DATAST-009 Android](0x00a_OMTG-DATAST_Android.md#OMTG-DATAST-009)
- [OMTG-DATAST-009 iOS](0x00b_OMTG-DATAST_iOS.md#OMTG-DATAST-009)

#### References

- OWASP MASVS: V2-1: "Verify that system credential storage facilities are used appropriately to store sensitive data, such as user credentials or cryptographic keys."
- CWE: [Link to CWE issue]
