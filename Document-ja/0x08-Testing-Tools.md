## テストツール

セキュリティテストを実行するためにさまざまなツールが利用できます。リクエストやレスポンスを操作したり、アプリを逆コンパイルしたり、実行中のアプリの挙動を調査したり、テストケースを自動化したりできます。

> MSTG プロジェクトには、以下のいずれのツールにこだわりを持ちませんし、いずれのツールの宣伝や販売にもこだわりません。以下のすべてのツールは「現役」であるかどうかを確認しています。つまり最近更新がプッシュされていることを意味しています。それでも、すべてのツールが執筆者により使用やテストされたわけではありませんが、モバイルアプリを解析するときにはおそらく役に立つかもしれません。リストはアルファベット順にソートされています。このリストには商用ツールも目を向けています。

### モバイルアプリケーションセキュリティテストディストリビューション

- [Androl4b](https://github.com/sh4hin/Androl4b "Androl4b") - Android アプリケーションの評価、リバースエンジニアリング、マルウェア解析のための仮想マシンです。
- [Android Tamer](https://androidtamer.com/ "Android Tamer") - Android Tamer は Android セキュリティ専門家向けの Debian ベースの仮想／ライブプラットフォームです。
- [Mobile Security Toolchain](https://github.com/xebia/mobilehacktools "Mobile Security Toolchain") - macOS を実行しているマシンで Android と iOS の両方でこのセクションで説明したツールの多くをインストールするために使用されるプロジェクトです。このプロジェクトは Ansible を介してツールをインストールします。

### オールインワンモバイルセキュリティフレームワーク

- [Appmon](https://github.com/dpnishant/appmon/ "Appmon") - AppMon はネイティブ macOS, iOS, android アプリのシステム API コールを監視および改竄するための自動化フレームワークです。
- [Mobile Security Framework - MobSF](https://github.com/ajinabraham/Mobile-Security-Framework-MobSF "Mobile Security Framework - MobSF") - MobSF は静的解析および動的解析を実行できるモバイルペンテストフレームワークです。
- [objection](https://github.com/sensepost/objection "objection") - objection は iOS および Android の両方に対応し、Frida を使用することにより、脱獄やルート化デバイスを必要としない実行時モバイルセキュリティ評価フレームワークです。

### 静的ソースコード解析 (商用ツール)

- [Checkmarx](https://www.checkmarx.com/technology/static-code-analysis-sca/ "Checkmarx") - 静的ソースコードスキャナであり、Android および iOS 用のソースコードもスキャンします。
- [Fortify](https://saas.hpe.com/en-us/software/fortify-on-demand/mobile-security "Fortify") - 静的ソースコードスキャナであり、Android および iOS 用のソースコードもスキャンします。
- [Veracode](https://www.veracode.com/products/binary-static-analysis-sast "Veracode") - 静的ソースコードスキャナであり、Android および iOS 用のバイナリもスキャンします。

### 動的解析および実行時解析

- [Frida](https://www.frida.re) - このツールキットはクライアントサーバーモデルを使用して動作し、Android および iOS の上で実行中のプロセスにインジェクトします。
- [Frida CodeShare](https://codeshare.frida.re/ "Frida CodeShare") - Frida CodeShare プロジェクトは Frida スクリプトを公開しています。これはモバイルアプリのクライアント側のセキュリティコントロール (SSL ピンニングなど) をバイパスするのに役立ちます。
- [NowSecure Workstation](https://www.nowsecure.com/solutions/power-tools-for-security-analysts/) (商用ツール) - モバイルアプリの脆弱性評価およびペネトレーションテスト用に事前設定されたハードウェアおよびソフトウェアキットです。

### リバースエンジニアリングおよび静的解析

- [Binary ninja](https://binary.ninja/ "Binary ninja") - Binary ninja はいくつかの実行可能ファイル形式に対して使用できるマルチプラットフォーム逆アセンブラです。IR (中間表現) リフティングが可能です。
- [Ghidra](https://ghidra-sre.org/ "Ghidra") - Ghidra は国家安全保障局 (NSA) により開発されたツールのオープンソースリバースエンジニアリングスイートです。主な機能には逆アセンブリ、アセンブリ、逆コンパイル、グラフ表示、スクリプト対応があります。
- [IDA Pro](https://www.hex-rays.com/products/ida/index.shtml "IDA Pro") (商用ツール) - IDA は Windows, Linux, macOS でホストされているマルチプロセッサ逆アセンブラおよびデバッガです。
- [Radare2](https://www.radare.org/r/ "Radare2") - Radare2 は Unix ライクなリバースエンジニアリングフレームワークおよびコマンドラインツールです。
- [Retargetable decompiler](https://retdec.com/ "Retdec") - RetDec は LLVM をベースとするオープンソースマシンコード逆コンパイラです。スタンドアロンプログラムとしても、IDA Pro や Radare2 のプラグインとしても使用できます。

### Android 用ツール

#### リバースエンジニアリングおよび静的解析

- [Androguard](https://github.com/androguard/androguard "Androguard") - Androguard は python ベースのツールで、Android アプリの逆アセンブルや逆コンパイルに使用できます。
- [Android Backup Extractor](https://github.com/nelenkov/android-backup-extractor "Android backup extractor") - adb backup (ICS 以降) で作成された Android バックアップを抽出および再パックするユーティリティです。主に AOSP の BackupManagerService.java をベースとしています。
- [Android Debug Bridge - adb](https://developer.android.com/studio/command-line/adb.html "Android Debug Bridge") - Android Debug Bridge (adb) はエミュレータインスタンスや接続された Android デバイスと通信するための多彩なコマンドラインツールです。
- [APKTool](https://ibotpeaches.github.io/Apktool/ "APKTool") - サードパーティ製でクローズなバイナリ Android アプリをリバースエンジニアリングするためのツールです。リソースをほぼ元の形にデコードし、改変後に再構築することができます。
- [android-classyshark](https://github.com/google/android-classyshark "android-classyshark") - ClassyShark は Android 開発者向けのスタンドアロンのバイナリインスペクションツールです。
- [ByteCodeViewer](https://bytecodeviewer.com/ "ByteCodeViewer") -  Java 8 Jar および Android APK のリバースエンジニアリングスイート (デコンパイラ、エディタ、デバッガなど) です。
- [ClassNameDeobfuscator](https://github.com/HamiltonianCycle/ClassNameDeobfuscator "ClassNameDeobfuscator") - apktool により生成される .smali ファイルを解析して .source アノテーション行を抽出するシンプルなスクリプトです。
- [FindSecurityBugs](https://find-sec-bugs.github.io "FindSecurityBugs") - FindSecurityBugs は SpotBugs の拡張機能であり、Java アプリケーション向けのセキュリティルールを含んでいます。
- [Jadx](https://github.com/skylot/jadx "Jadx") - Dex から Java へのデコンパイラです。Android Dex および Apk ファイルから Java ソースコードを生成するコマンドラインおよび GUI ツールです。
- [Oat2dex](https://github.com/testwhat/SmaliEx "Oat2dex") - .oat ファイルから .dex ファイルに変換するためのツールです。
- [Qark](https://github.com/linkedin/qark "Qark") - このツールは Android アプリケーション脆弱性に関連するいくつかのセキュリティをソースコードかパッケージ化された APK のいずれかで検索するように設計されています。
- [Sign](https://github.com/appium/sign "Sign") - Sign.jar は自動的に Android テスト証明書で apk に署名します。
- [Simplify](https://github.com/CalebFenton/simplify "Simplify") - Classes.dex 内の android パッケージを逆難読化するツールです。Dex2jar や JD-GUI を使用して dex ファイルの内容を抽出できます。
- [SUPER](https://github.com/SUPERAndroidAnalyzer/super "SUPER") - SUPER は Windows, macOS, Linux で使用できるコマンドラインアプリケーションで、.apk ファイルを検索して脆弱性を探します。
- [SpotBugs](https://spotbugs.github.io/ "SpotBugs") - Java 用の静的解析ツールです。

#### 動的解析および実行時解析

- [Android Tcpdump](https://www.androidtcpdump.com "TCPDump") - Android 用のコマンドラインパケットキャプチャユーティリティです。
- [Cydia Substrate: Introspy-Android](https://github.com/iSECPartners/Introspy-Android "Introspy Android") - Android アプリケーションが実行時に何をしているかを理解し、潜在的なセキュリティ問題の特定を支援するブラックボックスツールです。
- [Drozer](https://www.mwrinfosecurity.com/products/drozer/ "Drozer") - Drozer はアプリの役割を想定し、Dalvik VM と他のアプリの IPC エンドポイントや基礎をなす OS とのやり取りを行うことで、アプリやデバイスのセキュリティ脆弱性を検索することができます。
- [Inspeckage](https://github.com/ac-pm/Inspeckage "Inspeckage") - Inspeckage は Android アプリの動的解析を提供するために開発されたツールです。Android API の関数にフックを適用することで、Inspeckage は Android アプリケーションが実行時に何をしているのかを理解するのに役立ちます。
- [logcat-color](https://github.com/marshall/logcat-color "Logcat color") - Android SDK の adb logcat コマンドに代わるカラフルで高度な設定が可能なツールです。
- [VirtualHook](https://github.com/rk700/VirtualHook "VirtualHook") - VirtualHook は Android ART(>=5.0) のアプリケーション用のフッキングツールです。VirtualApp をベースにしており、フックを挿入するためにルート権限は必要ありません。
- [Xposed Framework](https://forum.xda-developers.com/xposed/xposed-installer-versions-changelog-t2714053 "Xposed Framework") - Xposed framework を使用すると、Android アプリケーションパッケージ (APK) の改変や再フラッシュを行わずに、実行時にシステムやアプリケーションのアスペクトや動作を変更できます。

#### ルート検出と証明書ピンニングのバイパス

- [Cydia Substrate Module: Android SSL Trust Killer](https://github.com/iSECPartners/Android-SSL-TrustKiller "Cydia Substrate Module: Android SSL Trust Killer") - デバイス上で動作するほとんどのアプリケーションの SSL 証明書ピンニングをバイパスするブラックボックスツールです。
- [Cydia Substrate Module: RootCoak Plus](https://github.com/devadvance/rootcloakplus "Cydia Substrate Module: RootCoak Plus") - 一般的に知られているルートの兆候に対するルートチェックにパッチを適用します。
- [Xposed Module: Just Trust Me](https://github.com/Fuzion24/JustTrustMe "Xposed Module: Just Trust Me") - SSL 証明書ピンニングをバイパスする Xposed モジュールです。
- [Xposed Module: SSLUnpinning](https://github.com/ac-pm/SSLUnpinning_Xposed "Xposed Module: SSLUnpinning") - SSL 証明書ピンニングをバイパスする Android Xposed モジュールです。

### iOS 用ツール

#### iDevice 上のファイルシステムへのアクセス

- [iFunbox](http://www.i-funbox.com "iFunbox") - iPhone, iPad, iPod Touch 向けのファイルおよびアプリ管理ツールです。
- [iProxy](https://github.com/tcurdt/iProxy "iProxy") - iProxy では USB 経由で接続する際に SSH 経由で脱獄済み iPhone に接続できます。
- [itunnel](https://code.google.com/p/iphonetunnel-usbmuxconnectbyport/downloads/list "itunnel") -  USB 経由で SSH を転送するために使用します。

脱獄済み iPhone に SSH できるようになると、以下のような FTP クライアントを使用してファイルシステムをブラウズすることができます。

- [Cyberduck](https://cyberduck.io "Cyberduck") - Mac および Windows 向けの Libre FTP, SFTP, WebDAV, S3, Azure & OpenStack Swift ブラウザです。
- [FileZilla](https://filezilla-project.org/download.php?show_all=1 "FireZilla") - FTP, SFTP, FTPS (FTP over SSL/TLS) をサポートしています。

#### リバースエンジニアリングおよび静的解析

- [class-dump](http://stevenygard.com/projects/class-dump/ "class-dump") - Mach-O ファイルに格納されている Objective-C ランタイム情報を調べるためのコマンドラインユーティリティです。
- [Clutch](https://github.com/KJCracks/Clutch "Clutch") - アプリケーションを解読し、バイナリや .ipa ファイルに指定された bundleID をダンプします。
- [Dumpdecrypted](https://github.com/stefanesser/dumpdecrypted "Dumpdecrypted") - 暗号化された iPhone アプリケーションから復号された mach-o ファイルをメモリからディスクにダンプします。
- [HopperApp](https://www.hopperapp.com/ "HopperApp") (Commercial Tool) - Hopper は macOS および Linux 用のリバースエンジニアリングツールで、32/64 ビット Intel Mac, Linux, Windows, iOS 実行可能ファイルを逆アセンブル、逆コンパイル、デバッグすることができます。
- [hopperscripts](https://github.com/Januzellij/hopperscripts "hopperscripts") - Hopperscripts を使用して、HopperApp の Swift 関数名をデマングルできます。
- [otool](https://www.unix.com/man-page/osx/1/otool/ "otool") - otool コマンドはオブジェクトファイルやライブラリの指定された箇所を表示します。
- [Plutil](https://www.theiphonewiki.com/wiki/Plutil "Plutil") - plutil は .plist ファイルをバイナリバージョンと XML バージョンの間で変換できるプログラムです。
- [Weak Classdump](https://github.com/limneos/weak_classdump "Weak Classdump") - 関数に渡されるクラスのヘッダファイルを生成する Cycript スクリプトです。classdump や dumpdecrypted ができない場合やバイナリが暗号化されている場合などにとても便利です。


#### 動的解析および実行時解析

- [bfinject](https://github.com/BishopFox/bfinject "bfinject") - bfinject は任意の dylib を実行中の App Store アプリにロードします。これには App Store アプリの復号化のサポートが組み込まれており、iSpy と Cycript がバンドルされています。
- [BinaryCookieReader](https://securitylearn.net/wp-content/uploads/tools/iOS/BinaryCookieReader.py "BinaryCookieReader") - バイナリ Cookies.binarycookies ファイルからすべてのクッキーをダンプするツールです。
- [Burp Suite Mobile Assistant](https://portswigger.net/burp/help/mobile_testing_using_mobile_assistant.html "Burp Suite Mobile Assistant") - 証明書ピンニングをバイパスし、アプリにインジェクトできるツールです。
- [cycript](http://www.cycript.org "cycript") - Cycript を使用すると、開発者は構文強調表示とタブ補完機能を備えた対話型コンソールを通じて Objective-C および JavaScript 構文をハイブリッドに使用して iOS もしくは macOS 上で実行中のアプリケーションを探索および改変できます。
- [Frida-cycript](https://github.com/nowsecure/frida-cycript "Frida-cycript") - これは Cycript のフォークで、ランタイムを Frida が提供する新しいランタイム Mjølner に置き換えました。これにより frida-cycript は frida-core によりメンテされているすべてのプラットフォームおよびアーキテクチャ上で実行できます。
- [Fridpa](https://github.com/tanprathan/Fridpa "Fridpa") - iOS アプリケーション (IPA ファイル) にパッチを適用するための自動ラッパースクリプトであり、非脱獄済みデバイスで動作します。
- [gdb](http://cydia.radare.org/debs/ "gdb") - iOS アプリケーションの実行時解析を行うためのツールです。
- [idb](https://github.com/dmayer/idb "idb") - idb は iOS ペネトレーションテストおよび研究のための一般的なタスクを簡素化するツールです。
- [Introspy-iOS](https://github.com/iSECPartners/Introspy-iOS "Introspy-iOS") - iOS アプリケーションが実行時に何をしているかを理解し、潜在的なセキュリティ問題の特定を支援するブラックボックスツールです
- [keychaindumper](http://cydia.radare.org/debs/ "keychaindumper") - iOS デバイスが脱獄された場合に攻撃者が利用可能となるキーチェーンアイテムを確認するためのツールです。
- [lldb](https://lldb.llvm.org/ "lldb") - Apple の Xcode に付属する LLDB デバッガは iOS アプリケーションをデバッグするために使用されます。
- [Needle](https://github.com/mwrlabs/needle "Needle") - Needle はモジュラフレームワークであり、バイナリ解析、静的コード解析、実行時操作などの iOS アプリのセキュリティ評価を行います。
- [Passionfruit](https://github.com/chaitin/passionfruit "Passionfruit") - 完全なウェブベースの GUI を備えたシンプルな iOS アプリブラックボックス評価ツールです。frida.re と vuejs により提供されています。

#### 脱獄検出および SSL ピンニングのバイパス

- [SSL Kill Switch 2](https://github.com/nabla-c0d3/ssl-kill-switch2 "SSL Kill Switch 2") - iOS および macOS アプリ内の SSL 証明書検証 (証明書ピンニングを含む) を無効にするブラックボックスツールです。
- [tsProtector](http://cydia.saurik.com/package/kr.typostudio.tsprotector8 "tsProtector 8") - 脱獄検出をバイパスするためのもうひとつのツールです。
- [Xcon](http://cydia.saurik.com/package/com.n00neimp0rtant.xcon/ "Xcon") - 脱獄検出をバイパスするためのツールです。

### ネットワーク傍受および監視用ツール

- [Canape](https://github.com/ctxis/canape "Canape") - 任意のプロトコル用のネットワークテストツールです。
- [Mallory](https://github.com/intrepidusgroup/mallory "Mallory") - モバイルデバイスやアプリケーションのトラフィックを監視および操作するために使用する中間者攻撃 (MiTM) ツールです。
- [MITM Relay](https://github.com/jrmdev/mitm_relay "MITM Relay") -
SSL および STARTTLS インターセプトをサポートする Burp などを介した非 HTTP プロトコルを傍受および改変します。
- [Tcpdump](https://www.tcpdump.org/ "TCPDump") - コマンドラインパケットキャプチャユーティリティです。
- [Wireshark](https://www.wireshark.org/download.html "WireShark") - オープンソースのパケットアナライザです。

### 傍受プロキシ

- [Burp Suite](https://portswigger.net/burp/download.html "Burp Suite") - Burp Suite はアプリケーションのセキュリティテストを実行するための統合プラットフォームです。
- [Charles Proxy](https://www.charlesproxy.com "Charles Proxy") - 開発者がマシンとインターネットの間のすべての HTTP および SSL / HTTPS トラフィックを表示することができる HTTP プロキシ / HTTP モニタ / リバースプロキシです。
- [Fiddler](https://www.telerik.com/fiddler "Fiddler") - Fiddler は HTTP および HTTPS トラフィックをキャプチャしてユーザーが確認するためにログに記録できる HTTP デバッグプロキシサーバーアプリケーションです。
- [OWASP ZAP](https://github.com/zaproxy/zaproxy "OWASP ZAP") - OWASP Zed Attack Proxy (ZAP) はウェブアプリケーションやウェブサービスのセキュリティ脆弱性を自動的に発見するのに役立つフリーのセキュリティツールです。
- [Proxydroid](https://github.com/madeye/proxydroid "Proxydroid") - Android システム用のグローバルプロキシアプリです。

### IDE

- [Android Studio](https://developer.android.com/studio/index.html "Android Studio") - Android Studio は Google の Android オペレーティングシステム向けの公式の統合開発環境 (IDE) です。JetBrains の IntelliJ IDEA ソフトウェアで構築されており、特に Android 開発向けに設計されています。
- [IntelliJ](https://www.jetbrains.com/idea/download/ "InteliJ") - IntelliJ IDEA はコンピュータソフトウェアを開発するための Java 統合開発環境 (IDE) です。
- [Eclipse](https://eclipse.org/ "Eclipse") - Eclipse はコンピュータプログラミングに使用される統合開発環境 (IDE) であり、最も広く使用されている Java IDE です。
- [Xcode](https://developer.apple.com/xcode/ "XCode") - Xcode は iOS, watchOS, tvOS, macOS 用のアプリを作成するための macOS 専用の統合開発環境 (IDE) です。

### 脆弱なアプリケーション

下記のアプリケーションはトレーニング教材として使用できます。注意：MSTG アプリと Crackmes のみが MSTG プロジェクトでテストおよび保守されています。

#### Android

- [Crackmes](https://github.com/OWASP/owasp-mstg/tree/master/Crackmes "Crackmes and license check") - Android アプリのハッキングスキルをテストするためのアプリケーションのセットです。
- [DVHMA](https://github.com/logicalhacking/DVHMA "Damn Vulnerable Hybrid Mobile App") - 意図的に脆弱性を含んでいるハイブリッドモバイルアプリ (Android 向け) です。
- [Digitalbank](https://github.com/CyberScions/Digitalbank "Android Digital Bank Vulnerable Mobile App") - 2015年に作られた脆弱なアプリで、古い Android プラットフォームで使用できます。
- [DIVA Android](https://github.com/payatu/diva-android "Damn insecure and vulnerable App") - 意図的にセキュアではないように設計されたアプリで、2016年に更新されており、13のさまざまな課題を含んでいます。
- [DodoVulnerableBank](https://github.com/CSPF-Founder/DodoVulnerableBank "Dodo Vulnerable Bank") - 2015年のセキュアではない Android アプリです。
- [InsecureBankv2](https://github.com/dineshshetty/Android-InsecureBankv2 "Insecure Bank V2") - セキュリティ愛好家や開発者がこの脆弱なアプリケーションをテストすることにより Android の危険性を知ることができます。2018年に更新され、多くの脆弱性を含んでいます。
- [MSTG Android app - Java](https://github.com/OWASP/MSTG-Hacking-Playground/tree/master/Android/OMTG-Android-App "OMTG Android App") - このドキュメントで説明されているテストケースと同様の脆弱性を持つ脆弱な Android アプリです。
- [MSTG Android app - Kotlin](https://github.com/OWASP/MSTG-Hacking-Playground/tree/master/Android/MSTG-Kotlin-App "MSTG Kotlin App") - このドキュメントで説明されているテストケースと同様の脆弱性を持つ脆弱な Android アプリです。

#### iOS

- [Crackmes](https://github.com/OWASP/owasp-mstg/tree/master/Crackmes "Crackmes and license check") - iOS アプリケーションのハッキングスキルをテストするアプリケーションのセットです。
- [Myriam](https://github.com/GeoSn0w/Myriam "Myriam iOS Security App") - iOS セキュリティの課題を持つ脆弱な iOS アプリです。
- [DVIA](https://github.com/prateek147/DVIA "Damn Vulnerable iOS App") - 脆弱な iOS アプリです。一連の脆弱性を持ち Objective-C で書かれています。追加のレッスンが [プロジェクトのウェブサイト](http://damnvulnerableiosapp.com/ "DVIA project website") にあります。
- [DVIA-v2](https://github.com/prateek147/DVIA-v2 "Damn Vulnerable iOS App v2") - 脆弱な iOS アプリです。Swift で書かれ、15以上の脆弱性があります。
- [iGoat](https://github.com/owasp/igoat "iGoat") - iGoat は iOS 開発者 (iPhone, iPad など) とモバイルアプリペンテスト担当者のための学習ツールです。WebGoat プロジェクトに触発され、同様の概念的な流れを持っています。
