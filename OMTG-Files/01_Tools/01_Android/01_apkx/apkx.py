#!/usr/bin/python
#
# apkx -- A Python wrapper for dex2jar and CFR. Use to extract and decompile Java code from Android APK.
# Because nobody likes messing with Java classpaths & command lines.
#
# Author: Bernhard Mueller
# This file is part of the OWASP Mobile Testing Guide (https://github.com/OWASP/owasp-mstg)
#
# See also:
#
# Dex2jar - https://github.com/pxb1988/dex2jar
# CFR - http://www.benf.org/other/cfr/
# 
# This program is free software: you can redistribute it and/or modify  
# it under the terms of the GNU General Public License as published by  
# the Free Software Foundation, version 3.

import os
import sys
import subprocess
import zipfile
import re

if len(sys.argv) < 2:
	print "Usage: " + sys.argv[0] + " <apkfile>"
	sys.exit(0)

apkfilename = sys.argv[1]

'''
	Unzip and decompile the application package.
'''

ext_path = os.path.splitext(os.path.basename(apkfilename))[0]

print("Extracting " + apkfilename + " to " + ext_path)

try:
	zip_ref = zipfile.ZipFile(apkfilename, 'r')
	zip_ref.extractall(ext_path)
	zip_ref.close()
except IOError as e:
	print("Error extracting apk: " + str(e))
	sys.exit(0)

'''
	Convert classes.dex to classes.jar using dex2jar
'''

try:
	subprocess.call(['java', '-Xms512m', '-Xmx1024m', '-cp', './apkx-libs.jar', 'com.googlecode.dex2jar.tools.Dex2jarCmd', ext_path + '/classes.dex', '-o', ext_path + '/classes.jar'])
except Exception as e:
	print('Error converting dex to jar:'+ str(e))
	sys.exit(0)

'''
	Decompile using CFR
'''

try:
	subprocess.call(['java','-Xms512m', '-Xmx1024m', '-cp', './apkx-libs.jar', 'org.benf.cfr.reader.Main', ext_path + '/classes.jar', '--outputdir', ext_path + '/src', '--caseinsensitivefs', 'true', '--silent', 'true'])
except Exception as e:
	print('Error decompiling:' + str(e))


