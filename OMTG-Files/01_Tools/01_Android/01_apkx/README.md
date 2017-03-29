# apkx - Extract Java Sources from APK Archives

A simple Python wrapper to dex2jar [1] and CFR [2]. Unzips the APK and decompiles Java bytecode contained in classes.dex.

## Installation

To download and install use:

$ wget https://raw.githubusercontent.com/OWASP/owasp-mstg/master/OMTG-Files/Download/apkx-0.9.tgz
$ tar xzf apkx-0.9.tgz
$ cd apkx-0.9
$ sudo ./install.sh

## Usage

Simply pass the APK filename on the command line:

~~~
$ apkx HelloWorld.apk 
Extracting HelloWorld.apk to HelloWorld
dex2jar HelloWorld/classes.dex -> HelloWorld/classes.jar
Decompiling to HelloWorld/src
$ ls HelloWorld/src/com/example/helloworld/
BuildConfig.java	MainActivity.java	R.java
~~~

## About

This file is part of the [OWASP Mobile Security Testing Guide](https://github.com/OWASP/owasp-mstg). See the chapter [Android Tampering and Reverse Engineering](https://github.com/OWASP/owasp-mstg/blob/master/Document/0x05c-Reverse-Engineering-and-Tampering.md) for further examples.

## References

- [1] dex2jar - https://github.com/pxb1988/dex2jar
- [2] CFR - http://www.benf.org/other/cfr/
