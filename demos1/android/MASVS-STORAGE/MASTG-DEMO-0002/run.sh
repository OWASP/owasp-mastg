#!/bin/bash

# SUMMARY: This script uses frida to trace files that an app has opened since it spawned
# The script filters the output of frida-trace to print only the paths belonging to external
# storage but the the predefined list of external storage paths might not be complete.
# A sample output is shown in "output.txt". If the output is empty, it indicates that no external
# storage is used.

frida \
    -U \
    -f org.owasp.mastestapp \
    -l script.js \
    -o output.txt
