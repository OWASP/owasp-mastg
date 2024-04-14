# Patterns of Concern
We specifically look for the following patterns in iOS applications to ensure sensitive data is handled securely:

- UserDefaults for Sensitive Data: Storing sensitive information, such as tokens or personal identifiers, in UserDefaults. This storage mechanism is not encrypted and can be easily accessed once the device is compromised.
- FileManager for Direct File Creation: Using FileManager to directly create files without encrypting the data first. These files can be included in backups and might be accessible to attackers or through data leaks.
- Loading Data with NSKeyedArchiver Without Secure Coding: Serializing objects using NSKeyedArchiver without requiring secure coding can lead to sensitive data being saved in an unencrypted form, posing a risk if the serialized data includes user information or credentials.
- Core Data Persistent Stores Without Encryption: Configuring Core Data without file encryption, which can result in the database being easily accessible and readable outside of the application's secure context.
- Disabling File Protection: Explicitly setting file protection attributes to none, thereby disabling the built-in encryption iOS provides for file storage. This makes the stored data vulnerable to unauthorized access.
- Checks for iCloud data sync, Keychain attribute misconfigurations, exclusion of files from backups using `NSURLIsExcludedFromBackupKey`, the use of Data Protection APIs, and ensuring Core Data encryption at rest.
