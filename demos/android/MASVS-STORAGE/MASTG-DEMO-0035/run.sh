#!/bin/bash

package_name="org.owasp.mastestapp"

../../../../utils/mastg-android-backup-adb.sh $package_name

ls -l1 apps/org.owasp.mastestapp/f > output.txt

# Cleanup
rm backup.ab backup.tar
find apps/org.owasp.mastestapp/ -mindepth 1 -maxdepth 1 ! -name 'f*' -exec rm -rf {} +
