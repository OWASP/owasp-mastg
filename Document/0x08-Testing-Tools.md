## Testing Tools

To perform security testing different tools are available in order to be able to manipulate requests and responses, decompile Apps, investigate the behavior of running Apps and other test cases and automate them.

> The MSTG project has no preference in any of the tools below, or in promoting or selling any of the tools. All tools below have been verified if they are "alive", meaning that updates have been pushed recently. Nevertheless, not all tools have been used/tested by the authors, but they might still be useful when analysing a mobile app. The listing is sorted in alphabetical order. The list is also pointing out commercial tools.

### Mobile Application Security Testing Distributions

 - Androl4b: A Virtual Machine For Assessing Android applications, Reverse Engineering and Malware Analysis - https://github.com/sh4hin/Androl4b
 - Android Tamer: Android Tamer is a Debian-based Virtual/Live Platform for Android Security professionals - https://androidtamer.com/
 - Mobile Security Toolchain: A project used to install many of the tools mentioned in this section, both for Android and iOS at a machine running macOS. The project installs the tools via Ansible - https://github.com/xebia/mobilehacktools

### All-in-One Mobile Security Frameworks

 - Appmon: AppMon is an automated framework for monitoring and tampering system API calls of native macOS, iOS and Android apps - https://github.com/dpnishant/appmon/
 - Mobile Security Framework - MobSF: MobSF is a mobile pen-testing framework, capable of performing static and dynamic analysis - https://github.com/ajinabraham/Mobile-Security-Framework-MobSF
 - objection: objection is a runtime mobile security assessment framework that does not require a jailbroken or rooted device for both iOS and Android, due to the usage of Frida - https://github.com/sensepost/objection

### Static Source Code Analysis (Commercial Tools)

 - Checkmarx: Static Source Code Scanner that also scans source code for Android and iOS - https://www.checkmarx.com/technology/static-code-analysis-sca/
 - Fortify: Static source code scanner that also scans source code for Android and iOS - https://saas.hpe.com/en-us/software/fortify-on-demand/mobile-security
 - Veracode: Static source code scanner that also scans binaries for Android and iOS - https://www.veracode.com/products/binary-static-analysis-sast

### Dynamic and Runtime Analysis

 - Frida: The toolkit works using a client-server model and lets you inject into running processes on Android and iOS - https://www.frida.re
 - Frida CodeShare: The Frida CodeShare project is hosting Frida scripts publicly that can help to bypass client side security controls in mobile apps (e.g. SSL Pinning) - https://codeshare.frida.re/
 - NowSecure Workstation (Commercial Tool): Pre-configured hardware and software kit for vulnerability assessment and penetration testing of mobile apps - https://www.nowsecure.com/solutions/power-tools-for-security-analysts/

### Reverse Engineering and Static Analysis

 - Binary ninja: Binary ninja is a multi-platform software disassembler that can be used against several executable file formats. It is capable of IR (intermediate representation) lifting - https://binary.ninja/
 - Ghidra: Ghidra is an open source software reverse engineering suite of tools developed by the National Security Agency (NSA). Its main capabilities include disassembly, assembly, decompilation, graphing, and scripting - https://ghidra-sre.org/
 - IDA Pro (Commercial Tool): IDA is a Windows, Linux or macOS hosted multi-processor disassembler and debugger - https://www.hex-rays.com/products/ida/index.shtml
 - Radare2: Radare2 is a unix-like reverse engineering framework and command line tools - https://www.radare.org/r/
 - Retargetable decompiler: RetDec is an open source machine-code decompiler based on LLVM. It can be used as a standalone program or as a plugin for IDA Pro or Radare2 - https://retdec.com/

### Tools for Android

#### Reverse Engineering and Static Analysis

 - Androguard: Androguard is a python based tool, which can use to disassemble and decompile Android apps - https://github.com/androguard/androguard
 - Android Backup Extractor: Utility to extract and repack Android backups created with adb backup (ICS+). Largely based on BackupManagerService.java from AOSP - https://github.com/nelenkov/android-backup-extractor
 - Android Debug Bridge: adb - Android Debug Bridge (adb) is a versatile command line tool that lets you communicate with an emulator instance or connected Android device - https://developer.android.com/studio/command-line/adb.html
 - APKTool: A tool for reverse engineering 3rd party, closed, binary Android apps. It can decode resources to nearly original form and rebuild them after making some modifications - https://ibotpeaches.github.io/Apktool/
 - android-classyshark: ClassyShark is a standalone binary inspection tool for Android developers - https://github.com/google/android-classyshark
 - ByteCodeViewer: Java 8 Jar and Android APK Reverse Engineering Suite (e.g. Decompiler, Editor and Debugger) - https://bytecodeviewer.com/
 - ClassNameDeobfuscator: Simple script to parse through the .smali files produced by apktool and extract the .source annotation lines - https://github.com/HamiltonianCycle/ClassNameDeobfuscator
 - FindSecurityBugs: FindSecurityBugs is a extension for SpotBugs which includes security rules for Java applications - https://find-sec-bugs.github.io
 - Jadx: Dex to Java decompiler: Command line and GUI tools for produce Java source code from Android Dex and Apk files - https://github.com/skylot/jadx
 - Oat2dex: A tool for converting .oat file to .dex files - https://github.com/testwhat/SmaliEx
 - Qark: This tool is designed to look for several security related Android application vulnerabilities, either in source code or packaged APKs - https://github.com/linkedin/qark
 - Sign: Sign.jar automatically signs an apk with the Android test certificate - https://github.com/appium/sign
 - Simplify: A tool for de-obfuscating android package into Classes.dex which can be use Dex2jar and JD-GUI to extract contents of dex file - https://github.com/CalebFenton/simplify
 - SUPER: SUPER is a command-line application that can be used in Windows, macOS and Linux, that analyzes .apk files in search for vulnerabilities - https://github.com/SUPERAndroidAnalyzer/super
 - SpotBugs: Static Analysis tool for Java - https://spotbugs.github.io/

#### Dynamic and Runtime Analysis

 - Android Tcpdump: A command line packet capture utility for Android - https://www.androidtcpdump.com
 - Cydia Substrate: Introspy-Android: Blackbox tool to help understand what an Android application is doing at runtime and assist in the identification of potential security issues - https://github.com/iSECPartners/Introspy-Android
 - Drozer: Drozer allows you to search for security vulnerabilities in apps and devices by assuming the role of an app and interacting with the Dalvik VM, other apps' IPC endpoints and the underlying OS - https://www.mwrinfosecurity.com/products/drozer/
 - Inspeckage: Inspeckage is a tool developed to offer dynamic analysis of Android apps. By applying hooks to functions of the Android API, Inspeckage will help you understand what an Android application is doing at runtime - https://github.com/ac-pm/Inspeckage
 - logcat-color: A colorful and highly configurable alternative to the adb logcat command from the Android SDK - https://github.com/marshall/logcat-color
 - VirtualHook: VirtualHook is a hooking tool for applications on Android ART(>=5.0). It's based on VirtualApp and therefore does not require root permission to inject hooks - https://github.com/rk700/VirtualHook
 - Xposed Framework: Xposed framework enables you to modify the system or application aspect and behavior at runtime, without modifying any Android application package(APK) or re-flashing - https://forum.xda-developers.com/xposed/xposed-installer-versions-changelog-t2714053
 - jdb: jdb is a Java Debugger which allows you to set breakpoints and print application variables. jdb uses the JDWP protocol - https://docs.oracle.com/javase/7/docs/technotes/tools/windows/jdb.html
 - AndBug: AndBug is a scriptable debugger targeting the Android platform's Dalvik virtual machine intended for reverse engineers and developers. AndBug is using the Java Debug Wire Protocol (JDWP) - https://github.com/swdunlop/AndBug
 - Introspy-Android: Blackbox tool to help understand what an Android application is doing at runtime and assist in the identification of potential security issues. Limitations: Introspy worked based on 'Cydia Substrate', so to work we need the Cydia and based on the app website Cydia, Supported Android on versions 2.3 through 4.3. On the mentioned version the Introspy does working correctly. (http://www.cydiasubstrate.com/) - https://github.com/iSECPartners/Introspy-Android

#### Bypassing Root Detection and Certificate Pinning

 - Cydia Substrate Module: Android SSL Trust Killer: Blackbox tool to bypass SSL certificate pinning for most applications running on a device - https://github.com/iSECPartners/Android-SSL-TrustKiller
 - Cydia Substrate Module: RootCoak Plus: Patch root checking for commonly known indications of root - https://github.com/devadvance/rootcloakplus
 - Xposed Module: Just Trust Me: Xposed Module to bypass SSL certificate pinning - https://github.com/Fuzion24/JustTrustMe
 - Xposed Module: SSLUnpinning: Android Xposed Module to bypass SSL Certificate Pinning - https://github.com/ac-pm/SSLUnpinning_Xposed

### Tools for iOS

#### Access Filesystem on iDevice

 - iFunbox: The File and App Management Tool for iPhone, iPad & iPod Touch - http://www.i-funbox.com
 - iProxy: With iProxy you can connect via SSH to your jailbroken iPhone when it's connected via USB - https://github.com/tcurdt/iProxy
 - itunnel: Use to forward SSH via USB - https://code.google.com/p/iphonetunnel-usbmuxconnectbyport/downloads/list

Once you are able to SSH into your jailbroken iPhone you can use an FTP client like the following to browse the file system:

 - Cyberduck: Libre FTP, SFTP, WebDAV, S3, Azure & OpenStack Swift browser for Mac and Windows - https://cyberduck.io
 - FileZilla: It supports FTP, SFTP, and FTPS (FTP over SSL/TLS) - https://filezilla-project.org/download.php?show_all=1

#### Reverse Engineering and Static Analysis

 - class-dump: A command-line utility for examining the Objective-C runtime information stored in Mach-O files - http://stevenygard.com/projects/class-dump/
 - Clutch: Decrypt the application and dump specified bundleID into binary or .ipa file - https://github.com/KJCracks/Clutch
 - Dumpdecrypted: Dumps decrypted mach-o files from encrypted iPhone applications from memory to disk - https://github.com/stefanesser/dumpdecrypted
 - HopperApp (Commercial Tool): Hopper is a reverse engineering tool for macOS and Linux, that lets you disassemble, decompile and debug your 32/64bits Intel Mac, Linux, Windows and iOS executables - https://www.hopperapp.com/
 - hopperscripts: Hopperscripts can be used to demangle the Swift function name in HopperApp - https://github.com/Januzellij/hopperscripts
 - otool: The otool command displays specified parts of object files or libraries - https://www.unix.com/man-page/osx/1/otool/
 - Plutil: plutil is a program that can convert .plist files between a binary version and an XML version - https://www.theiphonewiki.com/wiki/Plutil
 - Weak Classdump: A Cycript script that generates a header file for the class passed to the function. Most useful when you cannot use classdump or dumpdecrypted, when binaries are encrypted etc - https://github.com/limneos/weak_classdump


#### Dynamic and Runtime Analysis

 - bfinject: bfinject loads arbitrary dylibs into running App Store apps. It has built-in support for decrypting App Store apps, and comes bundled with iSpy and Cycript - https://github.com/BishopFox/bfinject
 - BinaryCookieReader: A tool to dump all the cookies from the binary Cookies.binarycookies file - https://securitylearn.net/wp-content/uploads/tools/iOS/BinaryCookieReader.py
 - Burp Suite Mobile Assistant: A tool to bypass certificate pinning and is able to inject into apps - https://portswigger.net/burp/help/mobile_testing_using_mobile_assistant.html
 - cycript: Cycript allows developers to explore and modify running applications on either iOS or macOS using a hybrid of Objective-C and JavaScript syntax through an interactive console that features syntax highlighting and tab completion - http://www.cycript.org
 - Frida-cycript: This is a fork of Cycript in which we replaced its runtime with a brand new runtime called Mjølner powered by Frida. This enables frida-cycript to run on all the platforms and architectures maintained by frida-core - https://github.com/nowsecure/frida-cycript
 - Fridpa: An automated wrapper script for patching iOS applications (IPA files) and work on non-jailbroken device - https://github.com/tanprathan/Fridpa
 - gdb: A tool to perform runtime analysis of iOS applications - http://cydia.radare.org/debs/
 - idb: idb is a tool to simplify some common tasks for iOS pentesting and research - https://github.com/dmayer/idb
 - Introspy-iOS: Blackbox tool to help understand what an iOS application is doing at runtime and assist in the identification of potential security issues - https://github.com/iSECPartners/Introspy-iOS
 - keychaindumper: A tool to check which keychain items are available to an attacker once an iOS device has been jailbroken - http://cydia.radare.org/debs/
 - lldb: LLDB debugger by Apple’s Xcode is used for debugging iOS applications - https://lldb.llvm.org/
 - Needle: Needle is a modular framework to conduct security assessments of iOS apps including Binary Analysis, Static Code Analysis and Runtime Manipulation - https://github.com/mwrlabs/needle
 - Passionfruit: Simple iOS app blackbox assessment tool with Fully web based GUI. Powered by frida.re and vuejs - https://github.com/chaitin/passionfruit

#### Bypassing Jailbreak Detection and SSL Pinning

 - SSL Kill Switch 2: Blackbox tool to disable SSL certificate validation - including certificate pinning - within iOS and macOS Apps - https://github.com/nabla-c0d3/ssl-kill-switch2
 - tsProtector: Another tool for bypassing Jailbreak detection - http://cydia.saurik.com/package/kr.typostudio.tsprotector8
 - Xcon: A tool for bypassing Jailbreak detection - http://cydia.saurik.com/package/com.n00neimp0rtant.xcon/

### Tools for Network Interception and Monitoring

 - Canape: A network testing tool for arbitrary protocols - https://github.com/ctxis/canape
 - Mallory: A Man in The Middle Tool (MiTM)) that is used to monitor and manipulate traffic on mobile devices and applications - https://github.com/intrepidusgroup/mallory
 - MITM Relay: - https://github.com/jrmdev/mitm_relay
Intercept and modify non-HTTP protocols through Burp and others with support for SSL and STARTTLS interception
 - Tcpdump: A command line packet capture utility - https://www.tcpdump.org/
 - Wireshark: An open-source packet analyzer - https://www.wireshark.org/download.html

### Interception Proxies

 - Burp Suite: Burp Suite is an integrated platform for performing security testing of applications - https://portswigger.net/burp/download.html
 - Charles Proxy: HTTP proxy / HTTP monitor / Reverse Proxy that enables a developer to view all of the HTTP and SSL / HTTPS traffic between their machine and the Internet - https://www.charlesproxy.com
 - Fiddler: Fiddler is an HTTP debugging proxy server application which can captures HTTP and HTTPS traffic and logs it for the user to review - https://www.telerik.com/fiddler
 - OWASP ZAP: The OWASP Zed Attack Proxy (ZAP) is a free security tool which can help you automatically find security vulnerabilities in your web applications and web services - https://github.com/zaproxy/zaproxy
 - Proxydroid: Global Proxy App for Android System - https://github.com/madeye/proxydroid

### IDEs

 - Android Studio: Android Studio is the official integrated development environment (IDE) for Google's Android operating system, built on JetBrains' IntelliJ IDEA software and designed specifically for Android development - https://developer.android.com/studio/index.html
 - IntelliJ: IntelliJ IDEA is a Java integrated development environment (IDE) for developing computer software - https://www.jetbrains.com/idea/download/
 - Eclipse: Eclipse is an integrated development environment (IDE) used in computer programming, and is the most widely used Java IDE - https://eclipse.org/
 - Xcode: Xcode is an integrated development environment (IDE) available only for macOS to create apps for iOS, watchOS, tvOS and macOS - https://developer.apple.com/xcode/

### Vulnerable applications

The applications listed below can be used as training materials. Note: only the MSTG apps and Crackmes are tested and maintained by the MSTG project.

#### Android

 - Crackmes: A set of apps to test your Android application hacking skills - https://github.com/OWASP/owasp-mstg/tree/master/Crackmes
 - DVHMA: A hybrid mobile app (for Android) that intentionally contains vulnerabilities - https://github.com/logicalhacking/DVHMA
 - Digitalbank: A vulnerable app created in 2015, which can be used on older Android platforms - https://github.com/CyberScions/Digitalbank
 - DIVA Android: An app intentionally designed to be insecure which has received updates in 2016 and contains 13 different challenges - https://github.com/payatu/diva-android
 - DodoVulnerableBank: An insecure Android app from 2015 - https://github.com/CSPF-Founder/DodoVulnerableBank
 - InsecureBankv2: A vulnerable Android app made for security enthusiasts and developers to learn the Android insecurities by testing a vulnerable application. It has been updated in 2018 and contains a lot of vulnerabilities - https://github.com/dineshshetty/Android-InsecureBankv2
 - MSTG Android app: Java - A vulnerable Android app with vulnerabilities similar to the test cases described in this document - https://github.com/OWASP/MSTG-Hacking-Playground/tree/master/Android/OMTG-Android-App
 - MSTG Android app: Kotlin - A vulnerable Android app with vulnerabilities similar to the test cases described in this document - https://github.com/OWASP/MSTG-Hacking-Playground/tree/master/Android/MSTG-Kotlin-App

#### iOS

 - Crackmes: A set of applications to test your iOS application hacking skills - https://github.com/OWASP/owasp-mstg/tree/master/Crackmes
 - Myriam: A vulnerable iOS app with iOS security challenges - https://github.com/GeoSn0w/Myriam
 - DVIA: http://damnvulnerableiosapp.com/
 - DVIA-v2: A vulnerable iOS app, written in Swift with over 15 vulnerabilities - https://github.com/prateek147/DVIA-v2
 - iGoat: iGoat is a learning tool for iOS developers (iPhone, iPad, etc.) and mobile app pentesters. It was inspired by the WebGoat project, and has a similar conceptual flow to it - https://github.com/owasp/igoat
