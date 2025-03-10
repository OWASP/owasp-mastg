#!/bin/bash
frida -U -f org.owasp.mastestapp -l ./script.js -o output.txt
python evaluate.py > evaluation.txt
