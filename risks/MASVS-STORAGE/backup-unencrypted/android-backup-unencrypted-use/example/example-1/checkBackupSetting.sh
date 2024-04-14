#!/bin/bash
# Check for allowBackup setting in AndroidManifest.xml
if grep 'android:allowBackup="true"' DisableBackupAndroidManifest.xml; then
  echo "FAIL: Unencrypted backup allowed. Set allowBackup to false."
else
  echo "PASS: Backup is securely configured or disabled."
fi