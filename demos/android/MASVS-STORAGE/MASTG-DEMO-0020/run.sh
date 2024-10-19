#!/bin/bash
# USAGE: ./run.sh <package name>
# EXAMPLE: ./run.sh org.owasp.mastestapp
# SUMMARY: List all files restored from a backup

# Script from https://developer.android.com/identity/data/testingbackup
# Initialize and create a backup
adb shell bmgr enable true
adb shell bmgr transport com.android.localtransport/.LocalTransport | grep -q "Selected transport" || (echo "Error: error selecting local transport"; exit 1)
adb shell settings put secure backup_local_transport_parameters 'is_encrypted=true'
adb shell bmgr backupnow "$1" | grep -F "Package $1 with result: Success" || (echo "Backup failed"; exit 1)

# Uninstall and reinstall the app to clear the data and trigger a restore
apk_path_list=$(adb shell pm path "$1")
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
adb shell pm uninstall --user 0 "$1"
apks=$(seq -f 'myapk%.f.apk' 1 $apk_number)
adb install-multiple -t --user 0 $apks

# Clean up
adb shell bmgr transport com.google.android.gms/.backup.BackupTransportService
rm $apks

echo "Done"


# Demo script
# You might need to enable root for ADB first with `adb root`
adb shell "find /data/user/0/org.owasp.mastestapp/ -type f" > output.txt
mkdir -p restored_files
while read -r line; do
  adb pull "$line" ./restored_files/
done < output.txt
