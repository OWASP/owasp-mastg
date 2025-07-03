#!/bin/bash
frida -U -f org.owasp.mastestapp -l ../MASTG-DEMO-0030/script.js -o output.txt