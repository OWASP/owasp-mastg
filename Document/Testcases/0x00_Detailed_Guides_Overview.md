# Detailed Guides

## Overview

### Testing Data Storage

#### OMTG-DATAST-001: Test Credential Storage

Mobile operating systems offer different native functions to store sensitive information like credentials and keys encrypted within the device. In case credentials or keys needs to be stored, several best practices available on the OS level should be applied to make it harder for attackers to retrieve these information. The following tasks should be done when analysing an App:

- Identify keys and passwords in the App, e.g. entered by the users, sent back by the endpoint, shipped within the App and how this sensitive data is processed locally.
- Decide with the developers if this sensitive stored information locally is needed and if not, how it can be removed or moved to the server (endpoint).

The credo for saving data can be summarized quite easy: Public data should be available for everybody, but sensitive and private data needs to be protected or not stored in the first place on the device itself.
This vulnerability can have many consequences, like disclosure of encryption keys that can be used by an attacker to decrypt information. More generally speaking an attacker might be able to identify these information to use it as a basis for other attacks like social engineering (when PII is disclosed), session hijacking (if session information or a token is disclosed) or gather information from apps that have a payment option in order to attack it.

This vulnerability occurs when sensitive data is not properly protected by an app when persistently storing it. The app might be able to store it in different places, for example locally on the device or on an external SD card. When trying to exploit this kind of issues, consider that there might be a lot of information processed and stored in different locations. It is important to identify at the beginning what kind of information is processed by the mobile application and keyed in by the user and what might be interesting and valuable for an attacker (e.g. passwords, credit card information).

#### OMTG-DATAST-002: Test for Sensitive Data Disclosure in Log Files

There are many legit reasons to create log files on a mobile device, for example to keep track of crashes or errors that are stored locally when being offline and being sent to the application developer/company once online again or for usage statistics. However, logging sensitive data such as credit card number and session IDs might expose the data to attackers or malicious applications.
Log files can be created in various ways on each of the different operating systems. The following list shows the mechanisms that are available on Android:

| Android                      | iOS           |
|:-----------------------------|:-------------|
|  Log Class, .log[a-Z]        | NSLog Method |
| Logger Class                 | printf-like function |
| StrictMode                   | NSAssert-like function |
| System.out/System.err.print  | Macro |

Classification of sensitive information can vary between different industries, countries and their laws and regulations. Therefore laws and regulations need to be known that are applicable to it and to be aware of what sensitive information actually is in the context of the App.

### OMTG-DATAST-003: Test for Sensitive Information in Cloud Storage

Android provides two ways for apps to backup their data to the cloud:
* Auto Backup for Apps (available >= API level 23), which uploads the data to the users Google Drive account.
* Key/Value Backup (Backup API), which uploads the data to the Anrdoid Backup Service.

### OMTG-DATAST-004: Test Data Communication with Third Parties

Different 3rd party services are available that can be embedded into the App to implement different features. This features can vary from tracker services to monitor the user behaviour within the App, selling banner advertisements or to create a better user experience. Interacting with these services abstracts the complexity and neediness to implement the functionality on it’s own and to reinvent the wheel.
The downside is that a developer doesn’t know in detail what code is executed via 3rd party libraries and therefore giving up visibility. Consequently it should be ensured that not more information as needed is sent to the service and that no sensitive information is disclosed.
3rd party services are mostly implemented in two ways:
* By using a standalone library, like a Jar in an Android project that is getting included into the APK.
* By using a full SDK.

#### OMTG-DATAST-005: Test for Sensitive Data in the Keyboard Cache
When keying in data into input fields, the software keyboard automatically suggests what data the user might want to key in. This feature can be very useful in messaging Apps to write text messages more efficient. For input fields that are asking for sensitive information like passwords or credit card data the keyboard cache might disclose sensitive information already when the input field is selected. This feature should therefore be disabled for input fields that are asking for sensitive information.

#### OMTG-DATAST-006: Test for Sensitive Data in the Clipboard
[General description]

#### OMTG-DATAST-007: Test for Sensitive Data Leakage via IPC Mechanisms
During development of mobile application, traditional techniques for IPC might be applied like usage of shared files or network sockets. As mobile application platforms implement their own system functionality for IPC these mechanisms should be applied as they are much more mature than traditional techniques. Using IPC mechanisms with no security in mind may cause the application to leak or expose sensitive data.

#### OMTG-DATAST-008: Test for Sensitive Data in the User Interface and Screenshots
Sensitive data could be exposed if a user deliberately takes a screenshot of the application (containing sensitive data), or in the case of malicious application running on the device, that is able to continuously capture the screen. For example, capturing a screenshot of a bank application running on the device may reveal information about the user account, his credit, transactions and so on.

#### OMTG-DATAST-009: Test for Sensitive Data in Backups
When backup options are available, it is important to consider that user data may be stored within application configuration data.  This feature could potentially leak sensitive information such as sessions, usernames, emails, passwords, keys and much more.
Consider to encrypt backup data and avoid to store any sensitive information that is not strictly required.

#### OMTG-DATAST-010: Test for Sensitive Data in the Backgrounded App
Manufacturers want to provide device users an aesthetically pleasing effect when an application is entered or exited, hence they introduced the concept of saving a screenshot when the application goes into the background. This feature could potentially pose a security risk for an application, as the screenshot containing sensitive information (e.g. a screenshot of an email or corporate documents) is written to local storage, where it is recovered either by a rogue application on a jailbroken device, or by someone who steals the device.

#### OMTG-DATAST-011: Test for Sensitive Data Disclosure in Process Memory

Analyzing the memory can help to identify the root cause of different problems, like for example why an application is crashing, but can also be used to identify sensitive data. This section describes how to check for sensitive data and disclosure of data in general within the process memory.

To be able to investigate the memory of an application a memory dump needs to be created first or the memory needs to be viewed with real-time updates. This is also already the problem, as the application only stores certain information in memory if certain functions are triggered within the application. Memory investigation can of course be executed randomly in every stage of the application, but it is much more beneficial to understand first what the mobile application is doing and what kind of functionalities it offers and also make a deep dive into the decompiled code before making any memory analysis.
Once sensitive functions are identified (like decryption of data) the investigation of a memory dump might be beneficial in order to identify sensitive data like a key or decrypted information.

#### OMTG-DATAST-012: Test Remote Locking and Wiping
[General description]

#### OMTG-DATAST-013: Test Enforcement of Device-Access-Security Policy
[General description]

### Testing Cryptography

### Testing Authentication and Session Management

### Testing Network Communication

### Testing Environmental Interaction

### Testing Code Quality and Build Settings

### Testing Resiliency against Reverse Engineering
