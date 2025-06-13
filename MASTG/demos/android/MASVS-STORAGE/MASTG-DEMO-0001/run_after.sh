#!/bin/bash

# SUMMARY: List all files created after the creation date of a file created in run_before

adb shell "find /sdcard/ -type f -newer /data/local/tmp/test_start" > output.txt
adb shell "rm /data/local/tmp/test_start"
mkdir -p new_files
while read -r line; do
  adb pull "$line" ./new_files/
done < output.txt
