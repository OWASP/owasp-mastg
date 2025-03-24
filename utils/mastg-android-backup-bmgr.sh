#!/bin/bash

# Default package name
if [ -z "$1" ]; then
    echo "No package name provided. Usage: $0 <package_name>"
    exit 1

else
    package_name="$1"
fi

# Script from https://developer.android.com/identity/data/testingbackup
# Initialize and create a backup
adb shell bmgr enable true
adb shell bmgr transport com.android.localtransport/.LocalTransport | grep -q "Selected transport" || (echo "Error: error selecting local transport"; exit 1)
adb shell settings put secure backup_local_transport_parameters 'is_encrypted=true'
adb shell bmgr backupnow "$package_name" | grep -F "Package $package_name with result: Success" || (echo "Backup failed"; exit 1)

# Uninstall and reinstall the app to clear the data and trigger a restore
apk_path_list=$(adb shell pm path "$package_name")
OIFS=$IFS
IFS=$'\n'
apk_number=0
for apk_line in $apk_path_list
do
    (( ++apk_number ))
    apk_path=${apk_line:8:1000}
    adb pull "$apk_path" "myapk${apk_number}.apk"
done
IFS=$OIFS
adb shell pm uninstall --user 0 "$package_name"
apks=$(seq -f 'myapk%.f.apk' 1 $apk_number)
adb install-multiple -t --user 0 $apks

# Clean up
adb shell bmgr transport com.google.android.gms/.backup.BackupTransportService
rm $apks

echo "Done"