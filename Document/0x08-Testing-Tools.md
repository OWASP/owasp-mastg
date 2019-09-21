## Testing Tools

To perform security testing different tools are available in order to be able to manipulate requests and responses, decompile apps, investigate the behavior of running apps and other test cases and automate them.

> The MSTG project has no preference in any of the tools below, or in promoting or selling any of the tools. All tools below have been verified if they are "alive", meaning that updates have been pushed recently. Nevertheless, not all tools have been used/tested by the authors, but they might still be useful when analyzing a mobile app. The listing is sorted in alphabetical order. The list is also pointing out commercial tools.

### Mobile Application Security Testing Distributions

- Androl4b: A virtual machine for assessing Android applications, perform reverse engineering and malware analysis - <https://github.com/sh4hin/Androl4b>
- Android Tamer: A Debian-based Virtual/Live Platform for Android Security professionals - <https://androidtamer.com/>
- Mobile Security Toolchain: A project used to install many of the tools mentioned in this section, both for Android and iOS at a machine running macOS. The project installs the tools via Ansible - <https://github.com/xebia/mobilehacktools>

### All-in-One Mobile Security Frameworks

- AppMon: An automated framework for monitoring and tampering system API calls of native macOS, iOS and Android apps - <https://github.com/dpnishant/appmon/>
- Mobile Security Framework (MobSF): A mobile pentesting framework, capable of performing static and dynamic analysis - <https://github.com/ajinabraham/Mobile-Security-Framework-MobSF>
- objection: A runtime mobile security assessment framework that does not require a jailbroken or rooted device for both iOS and Android, due to the usage of Frida - <https://github.com/sensepost/objection>

### Static Source Code Analysis (Commercial Tools)

- Checkmarx: Static Source Code Scanner that also scans source code for Android and iOS - <https://www.checkmarx.com/technology/static-code-analysis-sca/>
- Fortify: Static source code scanner that also scans source code for Android and iOS - <https://saas.hpe.com/en-us/software/fortify-on-demand/mobile-security>
- Veracode: Static source code scanner that also scans binaries for Android and iOS - <https://www.veracode.com/products/binary-static-analysis-sast>

### Dynamic and Runtime Analysis

- Frida: A dynamic instrumentation toolkit for developers, reverse-engineers, and security researchers. It works using a client-server model and allows to inject code into running processes on Android and iOS - <https://www.frida.re>
- Frida CodeShare: A project hosting Frida scripts publicly that can help to bypass client side security controls in mobile apps (e.g. SSL Pinning) - <https://codeshare.frida.re/>
- NowSecure Workstation (Commercial Tool): Pre-configured hardware and software kit for vulnerability assessment and penetration testing of mobile apps - <https://www.nowsecure.com/solutions/power-tools-for-security-analysts/>
- r2frida: A project merging the powerful reverse engineering capabilities of radare2 with the dynamic instrumentation toolkit of Frida <https://github.com/nowsecure/r2frida>

### Reverse Engineering and Static Analysis

- Binary ninja: A multi-platform software disassembler that can be used against several executable file formats. It is capable of IR (intermediate representation) lifting - <https://binary.ninja/>
- Ghidra: An open source software reverse engineering suite of tools developed by the National Security Agency (NSA). Its main capabilities include disassembly, assembly, decompilation, graphing, and scripting - <https://ghidra-sre.org/>
- HopperApp (Commercial Tool): A reverse engineering tool for macOS and Linux used to disassemble, decompile and debug 32/64bits Intel Mac, Linux, Windows and iOS executables - <https://www.hopperapp.com/>
- IDA Pro (Commercial Tool): A Windows, Linux or macOS hosted multi-processor disassembler and debugger - <https://www.hex-rays.com/products/ida/index.shtml>
- radare2: radare2 is a unix-like reverse engineering framework and command line tools - <https://www.radare.org/r/>
- Retargetable Decompiler (RetDec): An open source machine-code decompiler based on LLVM. It can be used as a standalone program or as a plugin for IDA Pro or radare2 - <https://retdec.com/>

### Tools for Android

#### Reverse Engineering and Static Analysis

- Androguard: A python based tool, which can use to disassemble and decompile Android apps - <https://github.com/androguard/androguard>
- Android Backup Extractor: Utility to extract and repack Android backups created with adb backup (ICS+). Largely based on BackupManagerService.java from AOSP - <https://github.com/nelenkov/android-backup-extractor>
- Android Debug Bridge (adb): A versatile command line tool used to communicate with an emulator instance or connected Android device - <https://developer.android.com/studio/command-line/adb.html>
- apktool: A tool for reverse engineering 3rd party, closed, binary Android apps. It can decode resources to nearly original form and rebuild them after making some modifications - <https://ibotpeaches.github.io/Apktool/>
- android-classyshark: A standalone binary inspection tool for Android developers - <https://github.com/google/android-classyshark>
- ByteCodeViewer: Java 8 Jar and Android APK Reverse Engineering Suite (e.g. Decompiler, Editor and Debugger) - <https://bytecodeviewer.com/>
- ClassNameDeobfuscator: Simple script to parse through the .smali files produced by apktool and extract the .source annotation lines - <https://github.com/HamiltonianCycle/ClassNameDeobfuscator>
- FindSecurityBugs: FindSecurityBugs is a extension for SpotBugs which includes security rules for Java applications - <https://find-sec-bugs.github.io>
- Jadx (Dex to Java Decompiler): Command line and GUI tools for producing Java source code from Android DEX and APK files - <https://github.com/skylot/jadx>
- Oat2dex: A tool for converting .oat file to .dex files - <https://github.com/testwhat/SmaliEx>
- Qark: A tool designed to look for several security related Android application vulnerabilities, either in source code or packaged APKs - <https://github.com/linkedin/qark>
- Sign: A Java JAR executable (Sign.jar) which automatically signs an APK with the Android test certificate - <https://github.com/appium/sign>
- Simplify: A tool for de-obfuscating android package into Classes.dex which can be use Dex2jar and JD-GUI to extract contents of DEX file - <https://github.com/CalebFenton/simplify>
- SUPER: A command-line application that can be used in Windows, macOS and Linux, that analyzes APK files in search for vulnerabilities - <https://github.com/SUPERAndroidAnalyzer/super>
- SpotBugs: Static analysis tool for Java - <https://spotbugs.github.io/>

#### Dynamic and Runtime Analysis

- Android Tcpdump: A command line packet capture utility for Android - <https://www.androidtcpdump.com>
- Drozer: A tool that allows to search for security vulnerabilities in apps and devices by assuming the role of an app and interacting with the Dalvik VM, other apps' IPC endpoints and the underlying OS - <https://www.mwrinfosecurity.com/products/drozer/>
- Inspeckage: A tool developed to offer dynamic analysis of Android apps. By applying hooks to functions of the Android API, Inspeckage helps to understand what an Android application is doing at runtime - <https://github.com/ac-pm/Inspeckage>
- jdb: A Java Debugger which allows to set breakpoints and print application variables. jdb uses the JDWP protocol - <https://docs.oracle.com/javase/7/docs/technotes/tools/windows/jdb.html>
- logcat-color: A colorful and highly configurable alternative to the adb logcat command from the Android SDK - <https://github.com/marshall/logcat-color>
- VirtualHook: A hooking tool for applications on Android ART (>=5.0). It's based on VirtualApp and therefore does not require root permission to inject hooks - <https://github.com/rk700/VirtualHook>
- Xposed Framework: A framework that allows to modify the system or application aspect and behavior at runtime, without modifying any Android application package (APK) or re-flashing - <https://forum.xda-developers.com/xposed/xposed-installer-versions-changelog-t2714053>

#### Bypassing Root Detection and Certificate Pinning

- Android SSL Trust Killer (Cydia Substrate Module): Blackbox tool to bypass SSL certificate pinning for most applications running on a device - <https://github.com/iSECPartners/Android-SSL-TrustKiller>
- JustTrustMe (Xposed Module): An Xposed Module to bypass SSL certificate pinning - <https://github.com/Fuzion24/JustTrustMe>
- RootCloak Plus (Cydia Substrate Module): Patch root checking for commonly known indications of root - <https://github.com/devadvance/rootcloakplus>
- SSLUnpinning (Xposed Module): An Xposed Module to bypass SSL certificate pinning - <https://github.com/ac-pm/SSLUnpinning_Xposed>

### Tools for iOS

#### Access Filesystem on iDevice

- iFunbox: The File and App Management Tool for iPhone, iPad & iPod Touch - <http://www.i-funbox.com>
- iProxy: A tool used to connect via SSH to a jailbroken iPhone via USB - <https://github.com/tcurdt/iProxy>
- itunnel: A tool used to forward SSH via USB - <https://code.google.com/p/iphonetunnel-usbmuxconnectbyport/downloads/list>

Once you are able to SSH into your jailbroken iPhone you can use an FTP client like the following to browse the file system:

- Cyberduck: Libre FTP, SFTP, WebDAV, S3, Azure & OpenStack Swift browser for Mac and Windows - <https://cyberduck.io>
- FileZilla: A solution supporting FTP, SFTP, and FTPS (FTP over SSL/TLS) - <https://filezilla-project.org/download.php?show_all=1>

#### Reverse Engineering and Static Analysis

- class-dump: A command-line utility for examining the Objective-C runtime information stored in Mach-O files - <http://stevenygard.com/projects/class-dump/>
- Clutch: Decrypt the application and dump specified bundleID into binary or IPA file - <https://github.com/KJCracks/Clutch>
- Dumpdecrypted: Dumps decrypted mach-o files from encrypted iPhone applications from memory to disk - <https://github.com/stefanesser/dumpdecrypted>
- hopperscripts: Collection of scripts that can be used to demangle Swift function names in HopperApp - <https://github.com/Januzellij/hopperscripts>
- otool: A tool that displays specified parts of object files or libraries - <https://www.unix.com/man-page/osx/1/otool/>
- Plutil: A program that can convert .plist files between a binary version and an XML version - <https://www.theiphonewiki.com/wiki/Plutil>
- Weak Classdump: A Cycript script that generates a header file for the class passed to the function. Most useful when classdump or dumpdecrypted cannot be used, when binaries are encrypted etc - <https://github.com/limneos/weak_classdump>

#### Dynamic and Runtime Analysis

- bfinject: A tool that loads arbitrary dylibs into running App Store apps. It has built-in support for decrypting App Store apps, and comes bundled with iSpy and Cycript - <https://github.com/BishopFox/bfinject>
- BinaryCookieReader: A tool to dump all the cookies from the binary Cookies.binarycookies file - <https://securitylearn.net/wp-content/uploads/tools/iOS/BinaryCookieReader.py>
- Burp Suite Mobile Assistant: A tool to bypass certificate pinning and is able to inject into apps - <https://portswigger.net/burp/help/mobile_testing_using_mobile_assistant.html>
- Cycript: A tool that allows developers to explore and modify running applications on either iOS or macOS using a hybrid of Objective-C and JavaScript syntax through an interactive console that features syntax highlighting and tab completion - <http://www.cycript.org>
- Frida-cycript: A fork of Cycript including a brand new runtime called Mjølner powered by Frida. This enables frida-cycript to run on all the platforms and architectures maintained by frida-core - <https://github.com/nowsecure/frida-cycript>
- Fridpa: An automated wrapper script for patching iOS applications (IPA files) and work on non-jailbroken device - <https://github.com/tanprathan/Fridpa>
- gdb: A tool to perform runtime analysis of iOS applications - <http://cydia.radare.org/debs/>
- idb: A tool to simplify some common tasks for iOS pentesting and research - <https://github.com/dmayer/idb>
- Introspy-iOS: Blackbox tool to help understand what an iOS application is doing at runtime and assist in the identification of potential security issues - <https://github.com/iSECPartners/Introspy-iOS>
- keychaindumper: A tool to check which keychain items are available to an attacker once an iOS device has been jailbroken - <http://cydia.radare.org/debs/>
- lldb: A debugger by Apple’s Xcode used for debugging iOS applications - <https://lldb.llvm.org/>
- Needle: A modular framework to conduct security assessments of iOS apps including Binary Analysis, Static Code Analysis and Runtime Manipulation - <https://github.com/mwrlabs/needle>
- Passionfruit: Simple iOS app blackbox assessment tool with Fully web based GUI. Powered by frida.re and vuejs - <https://github.com/chaitin/passionfruit>

#### Bypassing Jailbreak Detection and SSL Pinning

- SSL Kill Switch 2: Blackbox tool to disable SSL certificate validation - including certificate pinning - within iOS and macOS Apps - <https://github.com/nabla-c0d3/ssl-kill-switch2>
- tsProtector: A tool for bypassing Jailbreak detection - <http://cydia.saurik.com/package/kr.typostudio.tsprotector8>
- Xcon: A tool for bypassing Jailbreak detection - <http://cydia.saurik.com/package/com.n00neimp0rtant.xcon/>

### Tools for Network Interception and Monitoring

- bettercap: A powerful framework which aims to offer to security researchers and reverse engineers an easy to use, all-in-one solution for WiFi, Bluetooth Low Energy, wireless HID hijacking and Ethernet networks reconnaissance and MITM attacks - <https://www.bettercap.org/>
- Canape: A network testing tool for arbitrary protocols - <https://github.com/ctxis/canape>
- Mallory: A Man in The Middle Tool (MiTM) that is used to monitor and manipulate traffic on mobile devices and applications - <https://github.com/intrepidusgroup/mallory>
- MITM Relay: A script to intercept and modify non-HTTP protocols through Burp and others with support for SSL and STARTTLS interception - <https://github.com/jrmdev/mitm_relay>
- tcpdump: A command line packet capture utility - <https://www.tcpdump.org/>
- Wireshark: An open-source packet analyzer - <https://www.wireshark.org/download.html>

### Interception Proxies

- Burp Suite: An integrated platform for performing security testing of applications - <https://portswigger.net/burp/download.html>
- Charles Proxy: HTTP proxy / HTTP monitor / Reverse Proxy that enables a developer to view all of the HTTP and SSL / HTTPS traffic between their machine and the Internet - <https://www.charlesproxy.com>
- Fiddler: An HTTP debugging proxy server application which captures HTTP and HTTPS traffic and logs it for the user to review - <https://www.telerik.com/fiddler>
- OWASP Zed Attack Proxy (ZAP): A free security tool which helps to automatically find security vulnerabilities in web applications and web services - <https://github.com/zaproxy/zaproxy>
- Proxydroid: Global Proxy App for Android System - <https://github.com/madeye/proxydroid>

### IDEs

- Android Studio: The official IDE for Google's Android operating system, built on JetBrains' IntelliJ IDEA software and designed specifically for Android development - <https://developer.android.com/studio/index.html>
- IntelliJ IDEA: A Java IDE for developing computer software - <https://www.jetbrains.com/idea/download/>
- Eclipse: Eclipse is an IDE used in computer programming, and is the most widely used Java IDE - <https://eclipse.org/>
- Xcode: The official IDE to create apps for iOS, watchOS, tvOS and macOS. It's only available for macOS - <https://developer.apple.com/xcode/>

### Vulnerable applications

The applications listed below can be used as training materials. Note: only the MSTG apps and Crackmes are tested and maintained by the MSTG project.

#### Android

- Crackmes: A set of apps to test your Android application hacking skills - <https://github.com/OWASP/owasp-mstg/tree/master/Crackmes>
- AndroGoat: An open source vulnerable/insecure app using Kotlin. This app has a wide range of vulnerabilities related to certificate pinning, custom URL schemes, Android Network Security Configuration, WebViews, root detection and over 20 other vulnerabilities - <https://github.com/satishpatnayak/AndroGoat>
- DVHMA: A hybrid mobile app (for Android) that intentionally contains vulnerabilities - <https://github.com/logicalhacking/DVHMA>
- Digitalbank: A vulnerable app created in 2015, which can be used on older Android platforms - <https://github.com/CyberScions/Digitalbank>
- DIVA Android: An app intentionally designed to be insecure which has received updates in 2016 and contains 13 different challenges - <https://github.com/payatu/diva-android>
- DodoVulnerableBank: An insecure Android app from 2015 - <https://github.com/CSPF-Founder/DodoVulnerableBank>
- InsecureBankv2: A vulnerable Android app made for security enthusiasts and developers to learn the Android insecurities by testing a vulnerable application. It has been updated in 2018 and contains a lot of vulnerabilities - <https://github.com/dineshshetty/Android-InsecureBankv2>
- MSTG Android app: Java - A vulnerable Android app with vulnerabilities similar to the test cases described in this document - <https://github.com/OWASP/MSTG-Hacking-Playground/tree/master/Android/MSTG-Android-Java-App>
- MSTG Android app: Kotlin - A vulnerable Android app with vulnerabilities similar to the test cases described in this document - <https://github.com/OWASP/MSTG-Hacking-Playground/tree/master/Android/MSTG-Android-Kotlin-App>

#### iOS

- Crackmes: A set of applications to test your iOS application hacking skills - <https://github.com/OWASP/owasp-mstg/tree/master/Crackmes>
- Myriam: A vulnerable iOS app with iOS security challenges - <https://github.com/GeoSn0w/Myriam>
- DVIA: A vulnerable iOS app written in Objective-C which provides a platform to mobile security enthusiasts/professionals or students to test their iOS penetration testing skills - <http://damnvulnerableiosapp.com/>
- DVIA-v2: A vulnerable iOS app, written in Swift with over 15 vulnerabilities - <https://github.com/prateek147/DVIA-v2>
- iGoat: An iOS Objective-C app serving as a learning tool for iOS developers (iPhone, iPad, etc.) and mobile app pentesters. It was inspired by the WebGoat project, and has a similar conceptual flow to it - <https://github.com/owasp/igoat>
- iGoat-Swift: A Swift version of original iGoat project - <https://github.com/owasp/igoat-swift>
