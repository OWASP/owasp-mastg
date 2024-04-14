## external_storage_sensitive_data.yaml
Contains rules related to sensitive data being written to external storage on Android devices. It warns about ensuring that sensitive data is encrypted or not stored on external storage due to accessibility by any app with the appropriate permissions.

## sharedpreferences_sensitive_data.yaml
Warns about potential sensitive data stored in SharedPreferences on Android. It suggests ensuring that any stored information is not sensitive or is encrypted.

## missing_encryption_api_usage.yaml
Highlights potential handling of unencrypted sensitive data. It suggests reviewing the code to ensure that sensitive data is properly encrypted, especially when storing or retrieving data.

## backup-unencrypted-rule.yaml
Addresses the risk of unencrypted backups due to the allowBackup attribute being set to true in Android application settings. It recommends setting this attribute to false or implementing encryption to secure backups.

## cloud-backup-sensitive-data-rule.yaml
Focuses on the potential inclusion of sensitive data in cloud backups. It advises ensuring that sensitive information is encrypted before being sent to the cloud, particularly when the allowBackup attribute is enabled.

## insecure-device-conditions.yaml
The rule has two exclusion patterns. It will trigger if either:
The clientSideEncryption flag is missing, which is critical for ensuring that backups are encrypted at the client side.
The deviceToDeviceTransfer flag is absent, which is important for ensuring secure transfers between devices that support this feature.
