#!/bin/bash
if grep -qiE "isExcludedFromBackup|NSURLIsExcludedFromBackupKey" ./MASTestApp; then
    echo "This app appears to exclude files from backups; however, the developer may not be aware that the system does not guarantee these files will be excluded. To ensure the protection of this data, make sure to encrypt the file if you want to prevent it from being restored." > output.txt
else
    echo "This app doesn't seem to use 'ExcludedFromBackup' flag." > output.txt
fi
