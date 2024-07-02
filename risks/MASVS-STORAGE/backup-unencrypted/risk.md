Title: Backup Unencrypted 

Alias: backup-unencrypted 

Platform: [android, IOS] 

Profiles: [L2] 

Mappings: 
- masvs: [MASVS-STORAGE-2]
- mastg: [MASTG-TEST-0009, MASTG-TEST-0058]


## Overview
Mobile applications frequently store data, whether locally on the device, in external storage, or on cloud services. This data can range from non-sensitive app preferences to highly sensitive user information or cryptographic keys. The security of this data, especially when backed up, is paramount. Unencrypted backups pose a significant risk as they can be accessed by unauthorized individuals, potentially leading to data breaches.

## Impact
An attacker with access to an application's backup file can retrieve any unencrypted data that the application has backed up. As a result, any sensitive data exposed can be used by the attacker in future attacks or be readily exploited.

## Modes of Introduction
Default Settings: Most mobile operating systems do not encrypt backups by default, leading to potential data leakage.
Custom Solutions: Developers' custom backup solutions may not always implement encryption correctly.
Third-party Services: Use of third-party backup services without ensuring data is encrypted before transfer.
Development Practices: Encryption may be disabled for debugging purposes and not re-enabled for production releases.

## Migration
Encrypt Backup Data: Ensure all backup data is encrypted using strong encryption algorithms. Utilize platform features like Android's Backup Service API to encrypt data before it is backed up.
Secure Backup Keys: Store encryption keys securely using the platform's keystore mechanisms, such as the Android Keystore, to prevent unauthorized access to encryption keys.
Backup Access Controls: Implement strict access controls for backups, ensuring only authorized entities can access or restore the data.

## References
Android Developers Guide on Auto Backup for Apps: https://developer.android.com/guide/topics/data/autobackup#define-device-conditions 

## CVEs
CVE-2023-36620: Missing android:allowBackup="false" attribute leading to potential data exposure.
Additional CVE examples related to backup vulnerabilities include CVE-2017-16835, CVE-2017-15340, CVE-2017-7133, and CVE-2018-4172.

## Tests
Android
Refer to MASTG-TEST-0009 for testing backups for sensitive data on Android. Focus on ensuring the autoBackup feature's conditions are securely configured and that clientSideEncryption and deviceToDeviceTransfer options are properly utilized to safeguard the backup data.

## iOS
Refer to MASTG-TEST-0058 for guidance on testing backups for sensitive data on iOS platforms, with a particular emphasis on data protection APIs and iCloud backup settings.

