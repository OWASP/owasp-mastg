## Testing Tools

To perform security testing different tools are available in order to be able to manipulate requests and responses, decompile Apps, investigate the behavior of running Apps and other test cases and automate them.

### Mobile Application Security Testing Distributions

- [Appie](https://manifestsecurity.com/appie/ "Appie") - A portable software package for Android Pentesting and an awesome alternative to existing Virtual machines.
- [Androl4b](https://github.com/sh4hin/Androl4b "Androl4b") - A Virtual Machine For Assessing Android applications, Reverse Engineering and Malware Analysis
- [Android Tamer](https://androidtamer.com/ "Android Tamer") - Android Tamer is a Debian-based Virtual/Live Platform for Android Security professionals.
- [AppUse](https://appsec-labs.com/AppUse/ "Appuse") - AppUse is a Virtual Machine developed by AppSec Labs.
- [Mobisec](https://sourceforge.net/projects/mobisec/ "Mobisec") - Mobile security testing live environment.
- [Santoku](https://santoku-linux.com/ "Santoku") - Santoku is an OS and can be run outside a VM as a standalone operating system.
- [Mobile Security Toolchain](https://github.com/xebia/mobilehacktools "Mobile Security Toolchain") - A project used to install many of the tools mentioned in this section both for Android and iOS at a machine running Mac OSX. The project installs the tools via Ansible.
- [Vezir Project](https://github.com/oguzhantopgul/Vezir-Project "Vezir Project") - Mobile Application Pentesting and Malware Analysis Environment.

### Static Source Code Analysis

- [Checkmarx](https://www.checkmarx.com/technology/static-code-analysis-sca/ "Checkmarx") - Static Source Code Scanner that also scans source code for Android and iOS.
- [Fortify](https://saas.hpe.com/en-us/software/fortify-on-demand/mobile-security "Fortify") - Static source code scanner that also scans source code for Android and iOS.
- [Veracode](https://www.veracode.com/products/binary-static-analysis-sast "Veracode Static Analysis") - Static Analysis of iOS and Android binary

### All-in-One Mobile Security Frameworks

- [Appmon](https://github.com/dpnishant/appmon/ "Appmon") - AppMon is an automated framework for monitoring and tampering system API calls of native macOS, iOS and android apps.
- [Mobile Security Framework - MobSF](https://github.com/ajinabraham/Mobile-Security-Framework-MobSF "Mobile Security Framework - MobSF") - Mobile Security Framework is an intelligent, all-in-one open source mobile application (Android/iOS) automated pen-testing framework capable of performing static and dynamic analysis.
- [Needle](https://github.com/mwrlabs/needle "Needle") - Needle is an open source, modular framework to streamline the process of conducting security assessments of iOS apps including Binary Analysis, Static Code Analysis, Runtime Manipulation using Cycript and Frida hooking, and so on.
- [objection](https://github.com/sensepost/objection "objection") - objection is a runtime mobile security assessment framework that does not require a jailbroken or rooted device for both iOS and Android, due to the usage of Frida.

### Tools for Android

#### Reverse Engineering and Static Analysis

- [Androguard](https://github.com/androguard/androguard "Androguard") - Androguard is a python based tool, which can use to disassemble and  decompile android apps.
- [Android Debug Bridge - adb](https://developer.android.com/studio/command-line/adb.html "Android Debug Bridge") - Android Debug Bridge (adbis a versatile command line tool that lets you communicate with an emulator instance or connected Android device.
- [APKInspector](https://github.com/honeynet/apkinspector/ "APKInspector") - APKinspector is a powerful GUI tool for analysts to analyze the Android applications.
- [APKTool](https://ibotpeaches.github.io/Apktool/ "APKTool") - A tool for reverse engineering 3rd party, closed, binary Android apps. It can decode resources to nearly original form and rebuild them after making some modifications.
- [android-classyshark](https://github.com/google/android-classyshark "android-classyshark") - ClassyShark is a standalone binary inspection tool for Android developers.
- [Sign](https://github.com/appium/sign "Sign") - Sign.jar automatically signs an apk with the Android test certificate.
- [Jadx](https://github.com/skylot/jadx "Jadx") - Dex to Java decompiler: Command line and GUI tools for produce Java source code from Android Dex and Apk files.
- [Oat2dex](https://github.com/testwhat/SmaliEx "Oat2dex") - A tool for converting .oat file to .dex files.
- [FindBugs](http://findbugs.sourceforge.net "FindBugs") - Static Analysis tool for Java
- [FindSecurityBugs](https://find-sec-bugs.github.io "FindSecurityBugs") - FindSecurityBugs is a extension for FindBugs which include security rules for Java applications.
- [Qark](https://github.com/linkedin/qark "Qark") - This tool is designed to look for several security related Android application vulnerabilities, either in source code or packaged APKs.
- [SUPER](https://github.com/SUPERAndroidAnalyzer/super "SUPER") - SUPER is a command-line application that can be used in Windows, MacOS X and Linux, that analyzes .apk files in search for vulnerabilities. It does this by decompressing APKs and applying a series of rules to detect those vulnerabilities.
- [AndroBugs](https://github.com/AndroBugs/AndroBugs_Framework "AndroBugs") - AndroBugs Framework is an efficient Android vulnerability scanner that helps developers or hackers find potential security vulnerabilities in Android applications. No need to install on Windows.
- [Simplify](https://github.com/CalebFenton/simplify "Simplify") - A tool for de-obfuscating android package into Classes.dex which can be use Dex2jar and JD-GUI to extract contents of dex file.
- [ClassNameDeobfuscator](https://github.com/HamiltonianCycle/ClassNameDeobfuscator "ClassNameDeobfuscator") - Simple script to parse through the .smali files produced by apktool and extract the .source annotation lines.
- [Android backup extractor](https://github.com/nelenkov/android-backup-extractor "Android backup extractor") - Utility to extract and repack Android backups created with adb backup (ICS+). Largely based on BackupManagerService.java from AOSP.
- [VisualCodeGrepper](https://sourceforge.net/projects/visualcodegrepp/ "VisualCodeGrepper") - Static Code Analysis Tool for several programming languages including Java
- [ByteCodeViewer](https://bytecodeviewer.com/ "ByteCodeViewer") - Five different Java Decompiles, Two Bytecode Editors, A Java Compiler, Plugins, Searching, Supports Loading from Classes, JARs, Android APKs and More.

#### Dynamic and Runtime Analysis

- [Cydia Substrate](http://www.cydiasubstrate.com "Cydia Substrate") - Cydia Substrate for Android enables developers to make changes to existing software with Substrate extensions that are injected in to the target process's memory.
- [Xposed Framework](https://forum.xda-developers.com/xposed/xposed-installer-versions-changelog-t2714053 "Xposed Framework") - Xposed framework enables you to modify the system or application aspect and behavior at runtime, without modifying any Android application package(APKor re-flashing.
- [logcat-color](https://github.com/marshall/logcat-color "logcat-color") - A colorful and highly configurable alternative to the adb logcat command from the Android SDK.
- [Inspeckage](https://github.com/ac-pm/Inspeckage "Inspeckage") - Inspeckage is a tool developed to offer dynamic analysis of Android applications. By applying hooks to functions of the Android API, Inspeckage will help you understand what an Android application is doing at runtime.
- [Frida](https://www.frida.re "Frida") - The toolkit works using a client-server model and lets you inject in to running processes not just on Android, but also on iOS, Windows and Mac.
- [Diff-GUI](https://github.com/antojoseph/diff-gui "Diff-GUI") - A Web framework to start instrumenting with the avaliable modules, hooking on native, inject JavaScript using Frida.
- [House](https://github.com/nccgroup/house "House") - A runtime mobile application analysis toolkit with a Web GUI, powered by Frida, is designed for helping assess mobile applications by implementing dynamic function hooking and intercepting and intended to make Frida script writing as simple as possible.
- [AndBug](https://github.com/swdunlop/AndBug "AndBug") - AndBug is a debugger targeting the Android platform's Dalvik virtual machine intended for reverse engineers and developers.
- [Cydia Substrate: Introspy-Android](https://github.com/iSECPartners/Introspy-Android "Cydia Substrate: Introspy-Android") - Blackbox tool to help understand what an Android application is doing at runtime and assist in the identification of potential security issues.
- [Drozer](https://www.mwrinfosecurity.com/products/drozer/ "Drozer") - Drozer allows you to search for security vulnerabilities in apps and devices by assuming the role of an app and interacting with the Dalvik VM, other apps' IPC endpoints and the underlying OS.
- [VirtualHook](https://github.com/rk700/VirtualHook "VirtualHook") - VirtualHook is a hooking tool for applications on Android ART(>=5.0). It's based on VirtualApp and therefore does not require root permission to inject hooks.

#### Bypassing Root Detection and Certificate Pinning

- [Xposed Module: Just Trust Me](https://github.com/Fuzion24/JustTrustMe "Xposed Module: Just Trust Me") - Xposed Module to bypass SSL certificate pinning.
- [Xposed Module: SSLUnpinning](https://github.com/ac-pm/SSLUnpinning_Xposed "Xposed Module: SSLUnpinning") - Android Xposed Module to bypass SSL certificate validation (Certificate Pinning)).
- [Cydia Substrate Module: Android SSL Trust Killer](https://github.com/iSECPartners/Android-SSL-TrustKiller "Cydia Substrate Module: Android SSL Trust Killer") - Blackbox tool to bypass SSL certificate pinning for most applications running on a device.
- [Cydia Substrate Module: RootCoak Plus](https://github.com/devadvance/rootcloakplus "Cydia Substrate Module: RootCoak Plus") - Patch root checking for commonly known indications of root.
- [Android-ssl-bypass](https://github.com/iSECPartners/android-ssl-bypass "Android-ssl-bypass") - an Android debugging tool that can be used for bypassing SSL, even when certificate pinning is implemented, as well as other debugging tasks. The tool runs as an interactive console.
- [Frida CodeShare](https://codeshare.frida.re/ "Frida CodeShare") - The Frida CodeShare project is comprised of developers from around the world working together with one goal - push Frida to its limits in new and innovative ways.

#### Security Libraries

- [Java AES Crypto](https://github.com/tozny/java-aes-crypto "Java AES Crypto") - A simple Android class for encrypting & decrypting strings, aiming to avoid the classic mistakes that most such classes suffer from.
- [Proguard](https://www.guardsquare.com/en/products/proguard "Proguard") - ProGuard is a free Java class file shrinker, optimizer, obfuscator, and preverifier. It detects and removes unused classes, fields, methods, and attributes.
- [SQL Cipher](https://www.zetetic.net/sqlcipher/sqlcipher-for-android/ "SQL Cipher") - SQLCipher is an open source extension to SQLite that provides transparent 256-bit AES encryption of database files.
- [Secure Preferences](https://github.com/scottyab/secure-preferences "Secure Preferences") - Android Shared preference wrapper than encrypts the keys and values of Shared Preferences.
- [Trusted Intents](https://github.com/guardianproject/TrustedIntents "Trusted Intents") - Library for flexible trusted interactions between Android apps.
- [Capillary](https://github.com/google/capillary "Capillary") - Capillary is a library to simplify the sending of end-to-end encrypted push messages from Java-based application servers to Android clients.




### Tools for iOS

#### Access Filesystem on iDevice

- [FileZilla](https://filezilla-project.org/download.php?show_all=1 "FireZilla") -  It supports FTP, SFTP, and FTPS (FTP over SSL/TLS).
- [Cyberduck](https://cyberduck.io "Cyberduck") - Libre FTP, SFTP, WebDAV, S3, Azure & OpenStack Swift browser for Mac and Windows.
- [itunnel](https://code.google.com/p/iphonetunnel-usbmuxconnectbyport/downloads/list "itunnel") -  Use to forward SSH via USB.
- [iFunbox](http://www.i-funbox.com "iFunbox") - The File and App Management Tool for iPhone, iPad & iPod Touch.
- [iProxy](https://github.com/tcurdt/iProxy "iProxy") - Let's you connect your laptop to the iPhone to surf the web.

#### Reverse Engineering and Static Analysis

- [otool](https://www.unix.com/man-page/osx/1/otool/ "otool") - The otool command displays specified parts of object files or libraries.
- [Clutch](http://cydia.radare.org/ "Clutch") - Decrypted the application and dump specified bundleID into binary or .ipa file.
- [Dumpdecrypted](https://github.com/stefanesser/dumpdecrypted "Dumpdecrypted") - Dumps decrypted mach-o files from encrypted iPhone applications from memory to disk. This tool is necessary for security researchers to be able to look under the hood of encryption.
- [class-dump](http://stevenygard.com/projects/class-dump/ "class-dump") - A command-line utility for examining the Objective-C runtime information stored in Mach-O files.
- [Flex2](http://cydia.saurik.com/package/com.fuyuchi.flex2/ "Flex2") - Flex gives you the power to modify apps and change their behavior.
- [Weak Classdump](https://github.com/limneos/weak_classdump "Weak Classdump") - A Cycript script that generates a header file for the class passed to the function. Most useful when you cannot classdump or dumpdecrypted , when binaries are encrypted etc.
- [IDA Pro](https://www.hex-rays.com/products/ida/index.shtml "IDA Pro") - IDA is a Windows, Linux or Mac OS X hosted multi-processor disassembler and debugger that offers so many features it is hard to describe them all.
- [HopperApp](https://www.hopperapp.com/ "HopperApp") - Hopper is a reverse engineering tool for OS X and Linux, that lets you disassemble, decompile and debug your 32/64bits Intel Mac, Linux, Windows and iOS executables.
- [hopperscripts](https://github.com/Januzellij/hopperscripts "hopperscripts") - Hopperscripts can be used to demangle the Swift function name in HopperApp.
- [Radare2](https://www.radare.org/r/ "Radare2") - Radare2 is a unix-like reverse engineering framework and command line tools.
- [iRET](https://www.veracode.com/iret-ios-reverse-engineering-toolkit "iRET") - The iOS Reverse Engineering Toolkit is a toolkit designed to automate many of the common tasks associated with iOS penetration testing.
- [Plutil](https://www.theiphonewiki.com/wiki/Plutil "Plutil") - plutil is a program that can convert .plist files between a binary version and an XML version.

#### Dynamic and Runtime Analysis

- [cycript](http://www.cycript.org "cycript") - Cycript allows developers to explore and modify running applications on either iOS or Mac OS X using a hybrid of Objective-C++ and JavaScript syntax through an interactive console that features syntax highlighting and tab completion.
- [Frida-cycript](https://github.com/nowsecure/frida-cycript "Frida-cycript") - This is a fork of Cycript in which we replaced its runtime with a brand new runtime called Mjølner powered by Frida. This enables frida-cycript to run on all the platforms and architectures maintained by frida-core.
- [Fridpa](https://github.com/tanprathan/Fridpa "Fridpa") - An automated wrapper script for patching iOS applications (IPA files) and work on non-jailbroken device.
- [bfinject](https://github.com/BishopFox/bfinject "bfinject") - bfinject loads arbitrary dylibs into running App Store apps. It has built-in support for decrypting App Store apps, and comes bundled with iSpy and Cycript.
- [iNalyzer](https://appsec-labs.com/cydia/ "iNalyzer") - AppSec Labs iNalyzer is a framework for manipulating iOS applications, tampering with parameters and method.
- [Passionfruit](https://github.com/chaitin/passionfruit "Passionfruit") - Simple iOS app blackbox assessment tool with Fully web based GUI. Powered by frida.re and vuejs.
- [idb](https://github.com/dmayer/idb "idb") - idb is a tool to simplify some common tasks for iOS pentesting and research.
- [snoop-it](http://cydia.radare.org/ "snoop-it") - A tool to assist security assessments and dynamic analysis of iOS Apps.
- [Introspy-iOS](https://github.com/iSECPartners/Introspy-iOS "Introspy-iOS") - Blackbox tool to help understand what an iOS application is doing at runtime and assist in the identification of potential security issues.
- [gdb](http://cydia.radare.org/ "gdb") - A tool to perform runtime analysis of IOS applications.
- [lldb](https://lldb.llvm.org/ "lldb") - LLDB debugger by Apple’s Xcode is used for debugging iOS applications.
- [Apple configurator 2](https://itunes.apple.com/us/app/apple-configurator-2/id1037126344?mt=12 "Apple configurator 2") - A utility which can be used to view live system log on iDevice.
- [keychaindumper](http://cydia.radare.org/ "keychaindumper") - A tool to check which keychain items are available to an attacker once an iOS device has been jailbroken.
- [BinaryCookieReader](https://securitylearn.net/wp-content/uploads/tools/iOS/BinaryCookieReader.py "BinaryCookieReader") - A tool to dump all the cookies from the binary Cookies.binarycookies file.
- [Burp Suite Mobile Assistant](https://portswigger.net/burp/help/mobile_testing_using_mobile_assistant.html "Burp Suite Mobile Assistant") - A tool to bypass certificate pinning and is able to inject into apps.

#### Bypassing Root Detection and SSL Pinning

- [SSL Kill Switch 2](https://github.com/nabla-c0d3/ssl-kill-switch2 "SSL Kill Switch 2") - Blackbox tool to disable SSL certificate validation - including certificate pinning - within iOS and OS X Apps.
- [TrustKit](https://github.com/datatheorem/TrustKit "TrustKit") - TrustKit provides an easy-to-use API for deploying SSL public key pinning and reporting it in any iOS 10+, macOS 10.10+, tvOS 10+ or watchOS 3+ App; it supports both Swift and Objective-C Apps.
- [iOS TrustMe](https://github.com/intrepidusgroup/trustme "iOS TrustMe") - Disable certificate trust checks on iOS devices.
- [Xcon](http://cydia.saurik.com/package/com.n00neimp0rtant.xcon/ "Xcon") - A tool for bypassing Jailbreak detection.
- [tsProtector](http://cydia.saurik.com/package/kr.typostudio.tsprotector8 "tsProtector 8") - Another tool for bypassing Jailbreak detection.
- [Frida CodeShare](https://codeshare.frida.re/ "Frida CodeShare") - The Frida CodeShare project is comprised of developers from around the world working together with one goal - push Frida to its limits in new and innovative ways.

#### Security Libraries
- [OWASP iMAS](http://project-imas.github.io/ "OWASP iMAS") - iMAS is a collaborative research project from the MITRE Corporation focused on open source iOS security controls.

### Tools for Network Interception and Monitoring

- [Tcpdump](https://www.androidtcpdump.com "TCPDump") - A command line packet capture utility.
- [Wireshark](https://www.wireshark.org/download.html "WireShark") - An open-source packet analyzer.
- [Canape](https://github.com/ctxis/canape "Canape") - A network testing tool for arbitrary protocols.
- [Mallory](https://intrepidusgroup.com/insight/mallory/ "Mallory") - A Man in The Middle Tool (MiTM)) that is used to monitor and manipulate traffic on mobile devices and applications.

### Interception Proxies

- [Burp Suite](https://portswigger.net/burp/download.html "Burp Suite") - Burp Suite is an integrated platform for performing security testing of applications.
- [OWASP ZAP](https://github.com/zaproxy/zaproxy "OWASP ZAP") - The OWASP Zed Attack Proxy (ZAPis a free security tools which can help you automatically find security vulnerabilities in your web applications and web services.
- [Fiddler](https://www.telerik.com/fiddler "Fiddler") - Fiddler is an HTTP debugging proxy server application which can captures HTTP and HTTPS traffic and logs it for the user to review. Fiddler can also be used to modify HTTP traffic for troubleshooting purposes as it is being sent or received.
- [Charles Proxy](https://www.charlesproxy.com "Charles Proxy") - HTTP proxy / HTTP monitor / Reverse Proxy that enables a developer to view all of the HTTP and SSL / HTTPS traffic between their machine and the Internet.
- [Proxydroid](https://github.com/madeye/proxydroid) - Global Proxy App for Android System.

### IDEs

- [Android Studio](https://developer.android.com/studio/index.html "Android Studio") -  is the official integrated development environment (IDE) for Google's Android operating system, built on JetBrains' IntelliJ IDEA software and designed specifically for Android development.
- [IntelliJ](https://www.jetbrains.com/idea/download/ "InteliJ") - IntelliJ IDEA is a Java integrated development environment (IDE) for developing computer software.
- [Eclipse](https://eclipse.org/ "Eclipse") - Eclipse is an integrated development environment (IDE) used in computer programming, and is the most widely used Java IDE.
- [Xcode](https://developer.apple.com/xcode/ "XCode") - Xcode is an integrated development environment (IDE) available only for macOS to create apps for iOS, watchOS, tvOS and macOS.


### Vulnerable applications
The applications listed below can be used as training materials.

#### Android
- [DVHMA](https://github.com/logicalhacking/DVHMA "Damn Vulnerable Hybrid Mobile App") - A hybrid mobile app (for Android) that intentionally contains vulnerabilities.
- [Crackmes](https://github.com/OWASP/owasp-mstg/tree/master/Crackmes "Crackmes and license check") - A set of apps to test your Android application hacking skills.
- [OMTG Android app](https://github.com/OWASP/MSTG-Hacking-Playground) - A vulnerable Android app with vulnerabilities similar to the test cases described in this document.
- [Digitalbank](https://github.com/CyberScions/Digitalbank "Android Digital Bank Vulnerable Mobile App") - A vulnerable app created in 2015, which can be used on older Android platforms. Note: this is not tested by the authors.
- [DIVA Android](https://github.com/payatu/diva-android "Damn insecure and vulnerable App") - An app intentionally designed to be insecure which has received updates in 2016 and contains 13 different challenges. Note: this is not tested by the authors.
- [InsecureBankv2](https://github.com/dineshshetty/Android-InsecureBankv2 "Insecure Bank V2") - A vulnerable Android app made for security enthusiasts and developers to learn the Android insecurities by testing a vulnerable application. It has been updated in 2018 and contains a lot of vulnerabilities.
- [DodoVulnerableBank](https://github.com/CSPF-Founder/DodoVulnerableBank "Dodo Vulnerable Bank") - An insecure Android app from 2015. Note: this is not tested by the authors.



#### iOS

- [Crackmes](https://github.com/OWASP/owasp-mstg/tree/master/Crackmes "Crackmes and license check") - A set of applications to test your iOS application hacking skills.
- [Myriam](https://github.com/GeoSn0w/Myriam "Myriam iOS Security App") - A vulnerable iOS app with iOS security challenges.
- [DVIA](https://github.com/prateek147/DVIA "Damn Vulnerable iOS App") - A vulnerable iOS app, written in Objective-C with a set of vulnerabilities. Additional lessons can be found at [the projects website](http://damnvulnerableiosapp.com/ "DVIA project website").
- [DVIA-v2](https://github.com/prateek147/DVIA-v2 "Damn Vulnerable iOS App v2") - A vulnerable iOS app, written in Swift with over 15 vulnerabilities.
