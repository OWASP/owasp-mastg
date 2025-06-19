#!/bin/bash
NO_COLOR=true semgrep -c ../../../../rules/mastg-android-strictmode.yml ./MastgTest_reversed.java > output.txt
