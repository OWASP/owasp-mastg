# MASTG Backup Risks Folder Structure

This folder contains structured information for managing backup risks on Android and iOS platforms according to MASTG guidelines.

## Structure Overview

- `risk.md`: Contains a detailed overview of the unencrypted backup risk, its impact, modes of introduction, and migration strategies.
- `android-backup-unencrypted-use`: For Android applications using unencrypted backups.
  - `rules`: YAML files for static analysis checks.
  - `example`: Java and XML examples demonstrating risks and mitigation techniques.
- `ios-backup-unencrypted-use`: For iOS applications at risk of including sensitive data in unencrypted backups.
  - `rules`: detect_sensitive_data_storage.yaml: A Semgrep rule to identify potential storage of sensitive data in ways that might be included in backups. Encourages review to ensure data is encrypted and properly excluded from backups.
  - `example`: SensitiveDataStorageExample.swift: Demonstrates handling of data in ways that could be included in unencrypted backups, along with techniques to exclude or encrypt such data properly.
  - `run.sh`: Script to facilitate running static analysis against the Swift example code, providing findings that highlight areas needing secure data handling attention.

## Running the Examples and Rules

### Android

1. **Static Analysis Rules**:
   - Use tools like Semgrep with the provided YAML rules to automatically scan your Android project for potential backup risks.
   - Command example: `semgrep -f path/to/rule.yaml path/to/android/project`

2. **Examples**:
   - Review and run the example codes in your IDE or command line to understand the implications of unencrypted backups and how to mitigate them.
   - For shell scripts, make them executable (`chmod +x script.sh`) and run them directly.

### iOS

1. **Review Guidelines**:
   - Manually review your iOS project against the guidelines provided in the `rules` folder to ensure sensitive data is properly excluded from backups.
   
2. **Examples**:
   - Compile and run the Swift examples in Xcode to test excluding files from backups.
   - Modify the Swift code as needed to fit the specific paths and files in your application.

## Note
These examples and rules are provided as a starting point. Always customize and extend them according to your application's specific needs and backup practices.
