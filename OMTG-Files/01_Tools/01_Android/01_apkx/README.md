# apkx - Extract Java Sources from Android APK Archives

A simple Python wrapper to [dex2jar](https://github.com/pxb1988/dex2jar) and [CFR](http://www.benf.org/other/cfr/) that unzips an APK and decompiles Java bytecode contained in classes.dex.

## Installation

To download and install use:

```bash
$ wget https://raw.githubusercontent.com/OWASP/owasp-mstg/master/OMTG-Files/Download/apkx-0.9.tgz
$ tar xzf apkx-0.9.tgz
$ cd apkx-0.9
$ sudo ./install.sh
```

## Usage

Pass the APK filename on the command line:

```bash
$ apkx HelloWorld.apk 
Extracting HelloWorld.apk to HelloWorld
dex2jar HelloWorld/classes.dex -> HelloWorld/classes.jar
Decompiling to HelloWorld/src
$ ls HelloWorld/src/com/example/helloworld/
BuildConfig.java	MainActivity.java	R.java
```

## About

This script accompanies the [OWASP Mobile Security Testing Guide](https://github.com/OWASP/owasp-mstg). For further instructions and usage examples, see also:

- [Tampering and Reverse Engineering on Android](https://github.com/OWASP/owasp-mstg/blob/master/Document/0x05c-Reverse-Engineering-and-Tampering.md)
- [Testing Resiliency Against Reverse Engineering on Android](https://github.com/OWASP/owasp-mstg/blob/master/Document/0x05j-Testing-Resiliency-Against-Reverse-Engineering.md)

