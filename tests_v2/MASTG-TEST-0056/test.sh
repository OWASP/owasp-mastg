adb logcat | grep "$(adb shell ps | grep <package-name> | awk '{print $2}')" > output.txt
grep "PIN" output.txt