#!/bin/bash
NO_COLOR=true semgrep -c ../../../../rules/mastg-android-webview-allow-local-access.yml ./MastgTestWebView_reversed.java > output.txt