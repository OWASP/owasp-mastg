# Testing Data Storage and Privacy Issues

## Overview

Data Storage and privacy issues concerns about the availability of sensitive information within the shipped app, the file system of the mobile device or when it’s communicating to the defined endpoints. The app should be as lightweight as possible regarding the data it contains.

The definition of sensitive data might differ in different countries and/or industries through different laws and regulations. Examples of sensitive data might include:

- Personal Identifiable Information (PII), like date of birth, address or full name.
- Payment data (e.g. Credit Card data)
- Credentials
- IP addresses

To be able to look for sensitive data, it should first be defined and clear to all involved parties what sensitive data is in context of the App.

## Test Cases

### OMTG-DATAST-001: Test Sensitive Data Storage
[General description]

#### Detailed Guides

- [OMTG-DATAST-001 Android](0x00a_OMTG-DATAST_Android.md#OMTG-DATAST-001)
- [OMTG-DATAST-001 iOS](0x00b_OMTG-DATAST_iOS.md#OMTG-DATAST-001)

#### References

- OWASP MASVS: V2-1: "Verify that system credential storage facilities are used appropriately to store sensitive data, such as user credentials or cryptographic keys."
- CWE: [Link to CWE issue]

### OMTG-DATAST-002: Test for Sensitive Data Disclosure in Log Files
There are many legit reasons to create log files on a mobile device, for example to keep track of crashes or errors that are stored locally when being offline and being sent to the application developer/company once online again or for usage statistics. However, logging sensitive data such as credit card number and session IDs might expose the data to attackers or malicious applications.

#### Detailed Guides

- [OMTG-DATAST-002 Android](0x00a_OMTG-DATAST_Android.md#OMTG-DATAST-002)
- [OMTG-DATAST-002 iOS](0x00b_OMTG-DATAST_iOS.md#OMTG-DATAST-002)

#### References

- OWASP: [Link to MASVS]
- CWE: [Link to CWE issue]

### OMTG-DATAST-009: Test for Sensitive Data in Backups
[General description]

#### Detailed Guides

- [OMTG-DATAST-009 Android](0x00a_OMTG-DATAST_Android.md#OMTG-DATAST-009)
- [OMTG-DATAST-009 iOS](0x00b_OMTG-DATAST_iOS.md#OMTG-DATAST-009)

#### References

- OWASP MASVS: V2-1: "Verify that system credential storage facilities are used appropriately to store sensitive data, such as user credentials or cryptographic keys."
- CWE: [Link to CWE issue]
