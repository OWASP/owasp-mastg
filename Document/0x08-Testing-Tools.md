## Testing Tools

To perform security testing different tools are available in order to be able to manipulate requests and responses, decompile Apps, investigate the behavior of running Apps and other test cases and automate them.

> The MSTG project has no preference in any of the tools below, or in promoting or selling any of the tools. All tools below have been verified if they are "alive", meaning that updates have been pushed recently. Nevertheless, not all tools have been used/tested by the authors, but they might still be useful when analysing a mobile app. The listing is sorted in alphabetical order. The list is also pointing out commercial tools.

### Mobile Application Security Testing Distributions

- [Androl4b](https://github.com/sh4hin/Androl4b "Androl4b") - A Virtual Machine For Assessing Android applications, Reverse Engineering and Malware Analysis
- [Android Tamer](https://androidtamer.com/ "Android Tamer") - Android Tamer is a Debian-based Virtual/Live Platform for Android Security professionals.
- [Mobile Security Toolchain](https://github.com/xebia/mobilehacktools "Mobile Security Toolchain") - A project used to install many of the tools mentioned in this section, both for Android and iOS at a machine running macOS. The project installs the tools via Ansible.

### All-in-One Mobile Security Frameworks

- [Appmon](https://github.com/dpnishant/appmon/ "Appmon") - AppMon is an automated framework for monitoring and tampering system API calls of native macOS, iOS and Android apps.
- [Mobile Security Framework - MobSF](https://github.com/ajinabraham/Mobile-Security-Framework-MobSF "Mobile Security Framework - MobSF") - MobSF is a mobile pen-testing framework, capable of performing static and dynamic analysis.
- [objection](https://github.com/sensepost/objection "objection") - objection is a runtime mobile security assessment framework that does not require a jailbroken or rooted device for both iOS and Android, due to the usage of Frida.

### Static Source Code Analysis (Commercial Tools)

- [Checkmarx](https://www.checkmarx.com/technology/static-code-analysis-sca/ "Checkmarx") - Static Source Code Scanner that also scans source code for Android and iOS.
- [Fortify](https://saas.hpe.com/en-us/software/fortify-on-demand/mobile-security "Fortify") - Static source code scanner that also scans source code for Android and iOS.
- [Veracode](https://www.veracode.com/products/binary-static-analysis-sast "Veracode") - Static source code scanner that also scans binaries for Android and iOS.

### Dynamic and Runtime Analysis

- [Frida](https://www.frida.re) - The toolkit works using a client-server model and lets you inject into running processes on Android and iOS.
- [Frida CodeShare](https://codeshare.frida.re/ "Frida CodeShare") - The Frida CodeShare project is hosting Frida scripts publicly that can help to bypass client side security controls in mobile apps (e.g. SSL Pinning)
- [NowSecure Workstation](https://www.nowsecure.com/solutions/power-tools-for-security-analysts/) (Commercial Tool) - Pre-configured hardware and software kit for vulnerability assessment and penetration testing of mobile apps.

### Reverse Engineering and Static Analysis

- [Binary ninja](https://binary.ninja/ "Binary ninja") - Binary ninja is a multi-platform software disassembler that can be used against several executable file formats. It is capable of IR (intermediate representation) lifting. 
- [Ghidra](https://ghidra-sre.org/ "Ghidra") - Ghidra is an open source software reverse engineering suite of tools developed by the National Security Agency (NSA). Its main capabilities include disassembly, assembly, decompilation, graphing, and scripting.
- [IDA Pro](https://www.hex-rays.com/products/ida/index.shtml "IDA Pro") (Commercial Tool) - IDA is a Windows, Linux or macOS hosted multi-processor disassembler and debugger.
- [Radare2](https://www.radare.org/r/ "Radare2") - Radare2 is a unix-like reverse engineering framework and command line tools.
- [Retargetable decompiler](https://retdec.com/ "Retdec") - RetDec is an open source machine-code decompiler based on LLVM. It can be used as a standalone program or as a plugin for IDA Pro or Radare2.

### Tools for Android

#### Reverse Engineering and Static Analysis

- [Androguard](https://github.com/androguard/androguard "Androguard") - Androguard is a python based tool, which can use to disassemble and  decompile Android apps.
- [Android Backup Extractor](https://github.com/nelenkov/android-backup-extractor "Android backup extractor") - Utility to extract and repack Android backups created with adb backup (ICS+). Largely based on BackupManagerService.java from AOSP.
- [Android Debug Bridge - adb](https://developer.android.com/studio/command-line/adb.html "Android Debug Bridge") - Android Debug Bridge (adb) is a versatile command line tool that lets you communicate with an emulator instance or connected Android device.
- [APKTool](https://ibotpeaches.github.io/Apktool/ "APKTool") - A tool for reverse engineering 3rd party, closed, binary Android apps. It can decode resources to nearly original form and rebuild them after making some modifications.
- [android-classyshark](https://github.com/google/android-classyshark "android-classyshark") - ClassyShark is a standalone binary inspection tool for Android developers.
- [ByteCodeViewer](https://bytecodeviewer.com/ "ByteCodeViewer") -  Java 8 Jar and Android APK Reverse Engineering Suite (e.g. Decompiler, Editor and Debugger)
- [ClassNameDeobfuscator](https://github.com/HamiltonianCycle/ClassNameDeobfuscator "ClassNameDeobfuscator") - Simple script to parse through the .smali files produced by apktool and extract the .source annotation lines.
- [FindSecurityBugs](https://find-sec-bugs.github.io "FindSecurityBugs") - FindSecurityBugs is a extension for SpotBugs which includes security rules for Java applications.
- [Jadx](https://github.com/skylot/jadx "Jadx") - Dex to Java decompiler: Command line and GUI tools for produce Java source code from Android Dex and Apk files.
- [Oat2dex](https://github.com/testwhat/SmaliEx "Oat2dex") - A tool for converting .oat file to .dex files.
- [Qark](https://github.com/linkedin/qark "Qark") - This tool is designed to look for several security related Android application vulnerabilities, either in source code or packaged APKs.
- [Sign](https://github.com/appium/sign "Sign") - Sign.jar automatically signs an apk with the Android test certificate.
- [Simplify](https://github.com/CalebFenton/simplify "Simplify") - A tool for de-obfuscating android package into Classes.dex which can be use Dex2jar and JD-GUI to extract contents of dex file.
- [SUPER](https://github.com/SUPERAndroidAnalyzer/super "SUPER") - SUPER is a command-line application that can be used in Windows, macOS and Linux, that analyzes .apk files in search for vulnerabilities.
- [SpotBugs](https://spotbugs.github.io/ "SpotBugs") - Static Analysis tool for Java

#### Dynamic and Runtime Analysis

- [Android Tcpdump](https://www.androidtcpdump.com "TCPDump") - A command line packet capture utility for Android.
- [Cydia Substrate: Introspy-Android](https://github.com/iSECPartners/Introspy-Android "Introspy Android") - Blackbox tool to help understand what an Android application is doing at runtime and assist in the identification of potential security issues.
- [Drozer](https://www.mwrinfosecurity.com/products/drozer/ "Drozer") - Drozer allows you to search for security vulnerabilities in apps and devices by assuming the role of an app and interacting with the Dalvik VM, other apps' IPC endpoints and the underlying OS.
- [Inspeckage](https://github.com/ac-pm/Inspeckage "Inspeckage") - Inspeckage is a tool developed to offer dynamic analysis of Android apps. By applying hooks to functions of the Android API, Inspeckage will help you understand what an Android application is doing at runtime.
- [logcat-color](https://github.com/marshall/logcat-color "Logcat color") - A colorful and highly configurable alternative to the adb logcat command from the Android SDK.
- [VirtualHook](https://github.com/rk700/VirtualHook "VirtualHook") - VirtualHook is a hooking tool for applications on Android ART(>=5.0). It's based on VirtualApp and therefore does not require root permission to inject hooks.
- [Xposed Framework](https://forum.xda-developers.com/xposed/xposed-installer-versions-changelog-t2714053 "Xposed Framework") - Xposed framework enables you to modify the system or application aspect and behavior at runtime, without modifying any Android application package(APK) or re-flashing.

#### Bypassing Root Detection and Certificate Pinning

- [Cydia Substrate Module: Android SSL Trust Killer](https://github.com/iSECPartners/Android-SSL-TrustKiller "Cydia Substrate Module: Android SSL Trust Killer") - Blackbox tool to bypass SSL certificate pinning for most applications running on a device.
- [Cydia Substrate Module: RootCoak Plus](https://github.com/devadvance/rootcloakplus "Cydia Substrate Module: RootCoak Plus") - Patch root checking for commonly known indications of root.
- [Xposed Module: Just Trust Me](https://github.com/Fuzion24/JustTrustMe "Xposed Module: Just Trust Me") - Xposed Module to bypass SSL certificate pinning.
- [Xposed Module: SSLUnpinning](https://github.com/ac-pm/SSLUnpinning_Xposed "Xposed Module: SSLUnpinning") - Android Xposed Module to bypass SSL Certificate Pinning.

### Tools for iOS

#### Access Filesystem on iDevice

- [iFunbox](http://www.i-funbox.com "iFunbox") - The File and App Management Tool for iPhone, iPad & iPod Touch.
- [iProxy](https://github.com/tcurdt/iProxy "iProxy") - With iProxy you can connect via SSH to your jailbroken iPhone when it's connected via USB.
- [itunnel](https://code.google.com/p/iphonetunnel-usbmuxconnectbyport/downloads/list "itunnel") -  Use to forward SSH via USB.

Once you are able to SSH into your jailbroken iPhone you can use an FTP client like the following to browse the file system:

- [Cyberduck](https://cyberduck.io "Cyberduck") - Libre FTP, SFTP, WebDAV, S3, Azure & OpenStack Swift browser for Mac and Windows.
- [FileZilla](https://filezilla-project.org/download.php?show_all=1 "FireZilla") -  It supports FTP, SFTP, and FTPS (FTP over SSL/TLS).

#### Reverse Engineering and Static Analysis

- [class-dump](http://stevenygard.com/projects/class-dump/ "class-dump") - A command-line utility for examining the Objective-C runtime information stored in Mach-O files.
- [Clutch](https://github.com/KJCracks/Clutch "Clutch") - Decrypt the application and dump specified bundleID into binary or .ipa file.
- [Dumpdecrypted](https://github.com/stefanesser/dumpdecrypted "Dumpdecrypted") - Dumps decrypted mach-o files from encrypted iPhone applications from memory to disk.
- [HopperApp](https://www.hopperapp.com/ "HopperApp") (Commercial Tool) - Hopper is a reverse engineering tool for macOS and Linux, that lets you disassemble, decompile and debug your 32/64bits Intel Mac, Linux, Windows and iOS executables.
- [hopperscripts](https://github.com/Januzellij/hopperscripts "hopperscripts") - Hopperscripts can be used to demangle the Swift function name in HopperApp.
- [otool](https://www.unix.com/man-page/osx/1/otool/ "otool") - The otool command displays specified parts of object files or libraries.
- [Plutil](https://www.theiphonewiki.com/wiki/Plutil "Plutil") - plutil is a program that can convert .plist files between a binary version and an XML version.
- [Weak Classdump](https://github.com/limneos/weak_classdump "Weak Classdump") - A Cycript script that generates a header file for the class passed to the function. Most useful when you cannot use classdump or dumpdecrypted, when binaries are encrypted etc.


#### Dynamic and Runtime Analysis

- [bfinject](https://github.com/BishopFox/bfinject "bfinject") - bfinject loads arbitrary dylibs into running App Store apps. It has built-in support for decrypting App Store apps, and comes bundled with iSpy and Cycript.
- [BinaryCookieReader](https://securitylearn.net/wp-content/uploads/tools/iOS/BinaryCookieReader.py "BinaryCookieReader") - A tool to dump all the cookies from the binary Cookies.binarycookies file.
- [Burp Suite Mobile Assistant](https://portswigger.net/burp/help/mobile_testing_using_mobile_assistant.html "Burp Suite Mobile Assistant") - A tool to bypass certificate pinning and is able to inject into apps.
- [cycript](http://www.cycript.org "cycript") - Cycript allows developers to explore and modify running applications on either iOS or macOS using a hybrid of Objective-C and JavaScript syntax through an interactive console that features syntax highlighting and tab completion.
- [Frida-cycript](https://github.com/nowsecure/frida-cycript "Frida-cycript") - This is a fork of Cycript in which we replaced its runtime with a brand new runtime called Mjølner powered by Frida. This enables frida-cycript to run on all the platforms and architectures maintained by frida-core.
- [Fridpa](https://github.com/tanprathan/Fridpa "Fridpa") - An automated wrapper script for patching iOS applications (IPA files) and work on non-jailbroken device.
- [gdb](http://cydia.radare.org/debs/ "gdb") - A tool to perform runtime analysis of iOS applications.
- [idb](https://github.com/dmayer/idb "idb") - idb is a tool to simplify some common tasks for iOS pentesting and research.
- [Introspy-iOS](https://github.com/iSECPartners/Introspy-iOS "Introspy-iOS") - Blackbox tool to help understand what an iOS application is doing at runtime and assist in the identification of potential security issues.
- [keychaindumper](http://cydia.radare.org/debs/ "keychaindumper") - A tool to check which keychain items are available to an attacker once an iOS device has been jailbroken.
- [lldb](https://lldb.llvm.org/ "lldb") - LLDB debugger by Apple’s Xcode is used for debugging iOS applications.
- [Needle](https://github.com/mwrlabs/needle "Needle") - Needle is a modular framework to conduct security assessments of iOS apps including Binary Analysis, Static Code Analysis and Runtime Manipulation.
- [Passionfruit](https://github.com/chaitin/passionfruit "Passionfruit") - Simple iOS app blackbox assessment tool with Fully web based GUI. Powered by frida.re and vuejs.

#### Bypassing Jailbreak Detection and SSL Pinning

- [SSL Kill Switch 2](https://github.com/nabla-c0d3/ssl-kill-switch2 "SSL Kill Switch 2") - Blackbox tool to disable SSL certificate validation - including certificate pinning - within iOS and macOS Apps.
- [tsProtector](http://cydia.saurik.com/package/kr.typostudio.tsprotector8 "tsProtector 8") - Another tool for bypassing Jailbreak detection.
- [Xcon](http://cydia.saurik.com/package/com.n00neimp0rtant.xcon/ "Xcon") - A tool for bypassing Jailbreak detection.

### Tools for Network Interception and Monitoring

- [Canape](https://github.com/ctxis/canape "Canape") - A network testing tool for arbitrary protocols.
- [Mallory](https://github.com/intrepidusgroup/mallory "Mallory") - A Man in The Middle Tool (MiTM)) that is used to monitor and manipulate traffic on mobile devices and applications.
- [MITM Relay](https://github.com/jrmdev/mitm_relay "MITM Relay") -
Intercept and modify non-HTTP protocols through Burp and others with support for SSL and STARTTLS interception
- [Tcpdump](https://www.tcpdump.org/ "TCPDump") - A command line packet capture utility.
- [Wireshark](https://www.wireshark.org/download.html "WireShark") - An open-source packet analyzer.

### Interception Proxies

- [Burp Suite](https://portswigger.net/burp/download.html "Burp Suite") - Burp Suite is an integrated platform for performing security testing of applications.
- [Charles Proxy](https://www.charlesproxy.com "Charles Proxy") - HTTP proxy / HTTP monitor / Reverse Proxy that enables a developer to view all of the HTTP and SSL / HTTPS traffic between their machine and the Internet.
- [Fiddler](https://www.telerik.com/fiddler "Fiddler") - Fiddler is an HTTP debugging proxy server application which can captures HTTP and HTTPS traffic and logs it for the user to review.
- [OWASP ZAP](https://github.com/zaproxy/zaproxy "OWASP ZAP") - The OWASP Zed Attack Proxy (ZAP) is a free security tool which can help you automatically find security vulnerabilities in your web applications and web services.
- [Proxydroid](https://github.com/madeye/proxydroid "Proxydroid") - Global Proxy App for Android System.

### IDEs

- [Android Studio](https://developer.android.com/studio/index.html "Android Studio") - Android Studio is the official integrated development environment (IDE) for Google's Android operating system, built on JetBrains' IntelliJ IDEA software and designed specifically for Android development.
- [IntelliJ](https://www.jetbrains.com/idea/download/ "InteliJ") - IntelliJ IDEA is a Java integrated development environment (IDE) for developing computer software.
- [Eclipse](https://eclipse.org/ "Eclipse") - Eclipse is an integrated development environment (IDE) used in computer programming, and is the most widely used Java IDE.
- [Xcode](https://developer.apple.com/xcode/ "XCode") - Xcode is an integrated development environment (IDE) available only for macOS to create apps for iOS, watchOS, tvOS and macOS.

### Vulnerable applications

The applications listed below can be used as training materials. Note: only the MSTG apps and Crackmes are tested and maintained by the MSTG project.

#### Android

- [Crackmes](https://github.com/OWASP/owasp-mstg/tree/master/Crackmes "Crackmes and license check") - A set of apps to test your Android application hacking skills.
- [DVHMA](https://github.com/logicalhacking/DVHMA "Damn Vulnerable Hybrid Mobile App") - A hybrid mobile app (for Android) that intentionally contains vulnerabilities.
- [Digitalbank](https://github.com/CyberScions/Digitalbank "Android Digital Bank Vulnerable Mobile App") - A vulnerable app created in 2015, which can be used on older Android platforms.
- [DIVA Android](https://github.com/payatu/diva-android "Damn insecure and vulnerable App") - An app intentionally designed to be insecure which has received updates in 2016 and contains 13 different challenges.
- [DodoVulnerableBank](https://github.com/CSPF-Founder/DodoVulnerableBank "Dodo Vulnerable Bank") - An insecure Android app from 2015.
- [InsecureBankv2](https://github.com/dineshshetty/Android-InsecureBankv2 "Insecure Bank V2") - A vulnerable Android app made for security enthusiasts and developers to learn the Android insecurities by testing a vulnerable application. It has been updated in 2018 and contains a lot of vulnerabilities.
- [MSTG Android app - Java](https://github.com/OWASP/MSTG-Hacking-Playground/tree/master/Android/OMTG-Android-App "OMTG Android App") - A vulnerable Android app with vulnerabilities similar to the test cases described in this document.
- [MSTG Android app - Kotlin](https://github.com/OWASP/MSTG-Hacking-Playground/tree/master/Android/MSTG-Kotlin-App "MSTG Kotlin App") - A vulnerable Android app with vulnerabilities similar to the test cases described in this document.

#### iOS

- [Crackmes](https://github.com/OWASP/owasp-mstg/tree/master/Crackmes "Crackmes and license check") - A set of applications to test your iOS application hacking skills.
- [Myriam](https://github.com/GeoSn0w/Myriam "Myriam iOS Security App") - A vulnerable iOS app with iOS security challenges.
- [DVIA](https://github.com/prateek147/DVIA "Damn Vulnerable iOS App") - A vulnerable iOS app, written in Objective-C with a set of vulnerabilities. Additional lessons can be found at [the projects website](http://damnvulnerableiosapp.com/ "DVIA project website").
- [DVIA-v2](https://github.com/prateek147/DVIA-v2 "Damn Vulnerable iOS App v2") - A vulnerable iOS app, written in Swift with over 15 vulnerabilities.
- [iGoat](https://github.com/owasp/igoat "iGoat") - iGoat is a learning tool for iOS developers (iPhone, iPad, etc.) and mobile app pentesters. It was inspired by the WebGoat project, and has a similar conceptual flow to it.
