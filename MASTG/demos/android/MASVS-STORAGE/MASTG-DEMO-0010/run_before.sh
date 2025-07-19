#!/bin/bash

# SUMMARY: This script creates a dummy file to mark a timestamp that we can use later
# on to identify files created while the app was being exercised

adb shell "touch /data/local/tmp/test_start"
