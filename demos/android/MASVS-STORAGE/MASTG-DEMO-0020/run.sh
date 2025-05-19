#!/bin/bash

package_name="org.owasp.mastestapp"

adb root
adb shell "find /data/user/0/$package_name/files -type f" > output_before.txt

../../../../utils/mastg-android-backup-bmgr.sh $package_name

adb shell "find /data/user/0/$package_name/files -type f" > output_after.txt

mkdir -p restored_files
while read -r line; do
  adb pull "$line" ./restored_files/
done < output_after.txt
