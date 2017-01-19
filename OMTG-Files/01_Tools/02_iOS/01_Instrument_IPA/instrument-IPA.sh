#!/usr/bin/env bash
#
# A petty shell script for hacking a dylib into an existing iPhone package.
# Commonly used to inject FridaGadget.dylib.
# (C) bernhard [dot] mueller [at] owasp [dot] org
#
# This file is part of the OWASP Mobile Testing Guide (https://github.com/OWASP/owasp-mstg)
# 
# This program is free software: you can redistribute it and/or modify  
# it under the terms of the GNU General Public License as published by  
# the Free Software Foundation, version 3.

if [ $# -ne 4 ]
	then
		echo "Usage: $0 <IPA> <dylib_to_inject> <provisioning_profile> <signing_identity>"
		exit
fi

IPA=$1
DYLIB=$2
PROVISIONING_PROFILE=$3
SIGNING_IDENTITY=$4

TMP=/tmp/patchme

[ -d $TMP ] && rm -rf $TMP

mkdir -p $TMP

cp $IPA $TMP/patchme.ipa
unzip -qq $TMP/patchme.ipa -d $TMP/

APP_TMP_PATH=$(set -- "$TMP/Payload/"*.app; echo "$1")
MAINBIN=$(/usr/libexec/PlistBuddy -c "Print CFBundleExecutable" "$APP_TMP_PATH/Info.plist")

echo -e "### Temp path: $APP_TMP_PATH\n### Main executable: $MAINBIN"

# Replace provisioning profile

cp "$PROVISIONING_PROFILE" "$APP_TMP_PATH/embedded.mobileprovision"

# Insert dylib

cp "$DYLIB" "$APP_TMP_PATH/"

# Clean up

rm -rf $APP_TMP_PATH/_CodeSignature

# Insert LOAD command into the executable header.

echo "### Patching $MAINBIN..."
optool install -c load -p "@executable_path/$DYLIB" -t "$APP_TMP_PATH/$MAINBIN"

# Sign dylibs in the "Frameworks" directory:
# http://stackoverflow.com/questions/6896029/re-sign-ipa-iphone

echo "### Signing framework libraries..."

APP_FRAMEWORKS_PATH="$APP_TMP_PATH/Frameworks"

if [ -d "$APP_FRAMEWORKS_PATH" ]; then
for FRAMEWORK in "$APP_FRAMEWORKS_PATH/"*
do
    /usr/bin/codesign --force --sign "$SIGNING_IDENTITY" $FRAMEWORK
done
fi

echo "### Signing $DYLIB..."

/usr/bin/codesign --force --sign "$SIGNING_IDENTITY" "$APP_TMP_PATH/$DYLIB"

# Get entitlements from provisioning profile

security cms -D -i "$APP_TMP_PATH/embedded.mobileprovision" -o temp.plist
/usr/libexec/PlistBuddy -c "Print Entitlements" temp.plist -x > entitlements.plist

echo "Sign main executable: '$MAINBIN'..."

/usr/bin/codesign --force --sign "$SIGNING_IDENTITY" --entitlements entitlements.plist "$APP_TMP_PATH/$MAINBIN"

echo "### Launching via lldb..."

# Ready to launch!
# Self-modification doesn't work on non-jailbroken devices - except if we run the app in the debugger.

ios-deploy --debug --bundle "$APP_TMP_PATH/"

# rm -rf $TMP
