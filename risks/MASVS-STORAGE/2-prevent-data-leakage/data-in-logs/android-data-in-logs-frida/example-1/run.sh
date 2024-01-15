#!/bin/bash

# Note: the class and method names are case-sensitive

# Attach to the running app "Logging"
# Includes Log.v, Log.d, Log.i, Log.w, Log.e, Log.wtf, Logger
frida-trace -U -j "*Log*!*println*" Logging -o output.txt

## Spawn the app org.owasp.mastg.logging and trace the methods
# frida-trace -U -j "*Log*!*println*" -f org.owasp.mastg.logging -o output.txt

## System.err.print("key") => LoggingPrintStream.print()
# frida-trace -U -j "*LoggingPrintStream\!print" -f org.owasp.mastg.logging -o system_err_class_output.txt
