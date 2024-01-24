#!/bin/bash

# SUMMARY: This script uses frida-trace to trace logging statements in the specified Android app
# and filters the output to exclude certain log methods.
# The raw output is saved to "output_raw.txt" and then filtered to remove unwanted log entries.
# The final result saved to "output.txt".

frida-trace \
    -U \
    -f com.owasp.mas.maswebview \
    --runtime=v8 \
    -j 'android.util.Log!*' \
    -j 'java.util.logging.Logger!severe' \
    -o output_raw.txt \
    && cat output_raw.txt | grep -E "(Log|Logger)" | grep -vE "Log\.println|Log\.isLoggable" > output.txt
