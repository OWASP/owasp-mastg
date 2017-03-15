# apkx - Extract Java Sources from APK Archives

A simple Python wrapper to dex2jar [1] and CFR [2]. Unzips the APK and decompiles Java bytecode contained in classes.dex.

Usage:

~~~
$ python apkx.py MyPackage.apk 
Extracting MyPackage.apk to MyPackage
dex2jar MyPackage/classes.dex -> MyPackage/classes.jar
Processing MyPackage/classes.jar (use silent to silence)
Processing sg.vantagepoint.a
Processing sg.vantagepoint.uncrackablelevel1.MainActivity
Processing sg.vantagepoint.uncrackablelevel1.a
Processing sg.vantagepoint.uncrackablelevel1.b
~~~

This file is part of the OWASP Mobile Testing Guide.

- [1] dex2jar - https://github.com/pxb1988/dex2jar
- [2] CFR - http://www.benf.org/other/cfr/
