Demo Java Files:
InsecureStorageDemo.java and CloudBackupCheck.java demonstrate potential insecure storage practices that could lead to sensitive data being included in unencrypted backups. These examples align with illustrating the risk related to MASVS-STORAGE-2.

Detection Rules
- Unencrypted Android Backups: Detects when the allowBackup attribute is enabled, potentially leading to unencrypted data backups.
- Cloud Backup of Sensitive Data: Flags potential inclusion of sensitive data in cloud backups without proper exclusion settings.
- SharedPreferences Sensitive Data: Identifies usage of SharedPreferences to store sensitive data, which might not be encrypted by default.
- Missing Encryption in Data Handling: Highlights instances where sensitive data might be handled without apparent encryption, indicating a potential risk.
- External Storage Sensitive Data: Warns about writing sensitive data to external storage, which can be accessed by any app with the right permissions, without encrypting the data first.