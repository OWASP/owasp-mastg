## テストツール

セキュリティテストを実行するためにさまざまなツールが利用できます。リクエストやレスポンスを操作したり、アプリを逆コンパイルしたり、実行中のアプリの挙動を調査したり、テストケースを自動化したりできます。

> MSTG プロジェクトには、以下のいずれのツールにこだわりを持ちませんし、いずれのツールの宣伝や販売にもこだわりません。以下のすべてのツールは「現役」であるかどうかを確認しています。つまり最近更新がプッシュされていることを意味しています。それでも、すべてのツールが執筆者により使用やテストされたわけではありませんが、モバイルアプリを解析するときにはおそらく役に立つかもしれません。リストはアルファベット順にソートされています。このリストは商用ツールにも目を向けています。

### モバイルアプリケーションセキュリティテストディストリビューション

 - Androl4b: Android アプリケーションの評価するための仮想マシンです。リバースエンジニアリングとマルウェア解析を実行します。 - https://github.com/sh4hin/Androl4b
 - Android Tamer: Android セキュリティ専門家向けの Debian ベースの仮想／ライブプラットフォームです。 - https://androidtamer.com/
 - Mobile Security Toolchain: macOS を実行しているマシンで Android と iOS の両方に対して、このセクションで説明したツールの多くをインストールするために使用されるプロジェクトです。このプロジェクトは Ansible を介してツールをインストールします。 - https://github.com/xebia/mobilehacktools

### オールインワンモバイルセキュリティフレームワーク

 - AppMon: ネイティブ macOS, iOS, android アプリのシステム API コールを監視および改竄するための自動化フレームワークです。 - https://github.com/dpnishant/appmon/
 - Mobile Security Framework (MobSF): 静的解析および動的解析を実行できるモバイルペンテストフレームワークです。 - https://github.com/ajinabraham/Mobile-Security-Framework-MobSF
 - objection: iOS および Android の両方に対応し、Frida を使用することにより、脱獄済みデバイスやルート化デバイスを必要としない実行時モバイルセキュリティ評価フレームワークです。 - https://github.com/sensepost/objection

### 静的ソースコード解析 (商用ツール)

 - Checkmarx: Android および iOS 用のソースコードもスキャンする静的ソースコードスキャナです。 - https://www.checkmarx.com/technology/static-code-analysis-sca/
 - Fortify: Android および iOS 用のソースコードもスキャンする静的ソースコードスキャナです。 - https://saas.hpe.com/en-us/software/fortify-on-demand/mobile-security
 - Veracode: Android および iOS 用のバイナリもスキャンする静的ソースコードスキャナです。 - https://www.veracode.com/products/binary-static-analysis-sast

### 動的解析および実行時解析

 - Frida: 開発者、リバースエンジニア、セキュリティ研究者向けの動的計装ツールキットです。クライアントサーバーモデルを使用して動作し、Android および iOS の上で実行中のプロセスにインジェクトします。 - https://www.frida.re
 - Frida CodeShare: Frida スクリプトを公開しているプロジェクトで、モバイルアプリのクライアント側のセキュリティコントロール (SSL ピンニングなど) をバイパスするのに役立ちます。 - https://codeshare.frida.re/
 - NowSecure Workstation (商用ツール): モバイルアプリの脆弱性評価およびペネトレーションテスト用に事前設定されたハードウェアおよびソフトウェアキットです。 - https://www.nowsecure.com/solutions/power-tools-for-security-analysts/

### リバースエンジニアリングおよび静的解析

 - Binary ninja: 複数の実行可能ファイル形式に対して使用できるマルチプラットフォーム逆アセンブラです。IR (中間表現) リフティングが可能です。 - https://binary.ninja/
 - Ghidra: 国家安全保障局 (NSA) により開発されたツールのオープンソースリバースエンジニアリングスイートです。主な機能として逆アセンブリ、アセンブリ、逆コンパイル、グラフ表示、スクリプティングに対応しています。 - https://ghidra-sre.org/
 - HopperApp (商用ツール): 32/64 ビット Intel Mac, Linux, Windows, iOS 実行可能ファイルの逆アセンブル、逆コンパイル、デバッグに使用される、macOS および Linux 用のリバースエンジニアリングツールです。 - https://www.hopperapp.com/
 - IDA Pro (商用ツール): Windows, Linux, macOS でホストされているマルチプロセッサ逆アセンブラおよびデバッガです。 - https://www.hex-rays.com/products/ida/index.shtml
 - radare2: radare2 は Unix ライクなリバースエンジニアリングフレームワークおよびコマンドラインツールです。 - https://www.radare.org/r/
 - Retargetable Decompiler (RetDec): LLVM をベースとするオープンソースマシンコード逆コンパイラです。スタンドアロンプログラムとしても、IDA Pro や radare2 のプラグインとしても使用できます。 - https://retdec.com/

### Android 用ツール

#### リバースエンジニアリングおよび静的解析

 - Androguard: python ベースのツールで、Android アプリの逆アセンブルや逆コンパイルに使用できます。 - https://github.com/androguard/androguard
 - Android Backup Extractor: adb backup (ICS 以降) で作成された Android バックアップを抽出および再パックするユーティリティです。主に AOSP の BackupManagerService.java をベースとしています。 - https://github.com/nelenkov/android-backup-extractor
 - Android Debug Bridge (adb): エミュレータインスタンスや接続された Android デバイスと通信するために使用される多目的コマンドラインツールです。 - https://developer.android.com/studio/command-line/adb.html
 - ApkTool: サードパーティ製でクローズなバイナリ Android アプリをリバースエンジニアリングするためのツールです。リソースをほぼ元の形にデコードし、改変後に再構築することができます。 - https://github.com/iBotPeaches/Apktool
 - android-classyshark: Android 開発者向けのスタンドアロンのバイナリインスペクションツールです。 - https://github.com/google/android-classyshark
 - ByteCodeViewer: Java 8 Jar および Android APK のリバースエンジニアリングスイート (デコンパイラ、エディタ、デバッガなど) です。 - https://bytecodeviewer.com/
 - ClassNameDeobfuscator: apktool により生成される .smali ファイルを解析して .source アノテーション行を抽出するシンプルなスクリプトです。 - https://github.com/HamiltonianCycle/ClassNameDeobfuscator
 - FindSecurityBugs: FindSecurityBugs は SpotBugs の拡張機能であり、Java アプリケーション向けのセキュリティルールを含んでいます。 - https://find-sec-bugs.github.io
 - Jadx (Dex to Java Decompiler): Android Dex および Apk ファイルから Java ソースコードを生成するコマンドラインおよび GUI ツールです。 - https://github.com/skylot/jadx
 - Oat2dex: .oat ファイルから .dex ファイルに変換するためのツールです。 - https://github.com/testwhat/SmaliEx
 - Qark: セキュリティに関連する Android アプリケーション脆弱性をソースコードまたはパッケージ化された APK のいずれかで探索するように設計されたツールです。 - https://github.com/linkedin/qark
 - Sign: Android テスト証明書で自動的に apk に署名する Java JAR 実行形式ファイル (Sign.jar) です。 - https://github.com/appium/sign
 - Simplify: Classes.dex 内の android パッケージを逆難読化するツールです。Dex2jar や JD-GUI を使用して dex ファイルの内容を抽出できます。 - https://github.com/CalebFenton/simplify
 - SUPER: Windows, macOS, Linux で使用できるコマンドラインアプリケーションで、.apk ファイルを解析して脆弱性を探します。 - https://github.com/SUPERAndroidAnalyzer/super
 - SpotBugs: Java 用の静的解析ツールです。 - https://spotbugs.github.io/

#### 動的解析および実行時解析

 - Android Tcpdump: Android 用のコマンドラインパケットキャプチャユーティリティです。 - https://www.androidtcpdump.com
 - Drozer: アプリの役割を想定し、Dalvik VM と他のアプリの IPC エンドポイントや基礎をなす OS とのやり取りを行うことで、アプリやデバイスのセキュリティ脆弱性を検索できるツールです。 - https://www.mwrinfosecurity.com/products/drozer/
 - Inspeckage: Android アプリの動的解析を提供するために開発されたツールです。Android API の関数にフックを適用することで、Inspeckage は Android アプリケーションが実行時に何をしているのかを理解するのに役立ちます。 - https://github.com/ac-pm/Inspeckage
 - jdb: ブレークポイントを設定したりアプリケーション変数を表示したりできる Java デバッガです。jdb は JDWP プロトコルを使用します。 - https://docs.oracle.com/javase/7/docs/technotes/tools/windows/jdb.html
 - logcat-color: Android SDK の adb logcat コマンドに代わるカラフルで高度な設定が可能なツールです。 - https://github.com/marshall/logcat-color
 - VirtualHook: Android ART(>=5.0) のアプリケーション用のフッキングツールです。VirtualApp をベースにしており、フックを挿入するためにルート権限は必要ありません。 - https://github.com/rk700/VirtualHook
 - Xposed Framework: Android アプリケーションパッケージ (APK) の改変や再フラッシュを行わずに、実行時にシステムやアプリケーションのアスペクトや動作を変更できるフレームワークです。 - https://forum.xda-developers.com/xposed/xposed-installer-versions-changelog-t2714053

#### ルート検出と証明書ピンニングのバイパス

 - Android SSL Trust Killer (Cydia Substrate Module): デバイス上で動作するほとんどのアプリケーションの SSL 証明書ピンニングをバイパスするブラックボックスツールです。 - https://github.com/iSECPartners/Android-SSL-TrustKiller
 - JustTrustMe (Xposed Module): SSL 証明書ピンニングをバイパスする Xposed モジュールです。 - https://github.com/Fuzion24/JustTrustMe
 - RootCloak Plus (Cydia Substrate Module): 一般的に知られているルートの兆候に対するルートチェックにパッチを適用します。 - https://github.com/devadvance/rootcloakplus
 - SSLUnpinning (Xposed Module): SSL 証明書ピンニングをバイパスする Xposed モジュールです。 - https://github.com/ac-pm/SSLUnpinning_Xposed

### iOS 用ツール

#### iDevice 上のファイルシステムへのアクセス

 - iFunbox: iPhone, iPad, iPod Touch 向けのファイルおよびアプリ管理ツールです。 - http://www.i-funbox.com
 - iProxy: USB 経由で脱獄済み iPhone に SSH 接続するために使用されるツールです。 - https://github.com/tcurdt/iProxy
 - itunnel: USB 経由で SSH を転送するために使用されるツールです。 - https://code.google.com/p/iphonetunnel-usbmuxconnectbyport/downloads/list

脱獄済み iPhone に SSH できるようになると、以下のような FTP クライアントを使用してファイルシステムをブラウズすることができます。

 - Cyberduck: Mac および Windows 向けの Libre FTP, SFTP, WebDAV, S3, Azure & OpenStack Swift ブラウザです。 - https://cyberduck.io
 - FileZilla: FTP, SFTP, FTPS (FTP over SSL/TLS) をサポートしているソリューションです。 - https://filezilla-project.org/download.php?show_all=1

#### リバースエンジニアリングおよび静的解析

 - class-dump: Mach-O ファイルに格納されている Objective-C ランタイム情報を調べるためのコマンドラインユーティリティです。 - http://stevenygard.com/projects/class-dump/
 - Clutch: アプリケーションを解読し、バイナリや .ipa ファイル内に指定された bundleID をダンプします。 - https://github.com/KJCracks/Clutch
 - Dumpdecrypted: 暗号化された iPhone アプリケーションから復号された mach-o ファイルをメモリからディスクにダンプします。 - https://github.com/stefanesser/dumpdecrypted
 - hopperscripts: HopperApp の Swift 関数名をデマングルするために使用できるスクリプトのコレクションです。 - https://github.com/Januzellij/hopperscripts
 - otool: オブジェクトファイルやライブラリの指定された箇所を表示するツールです。 - https://www.unix.com/man-page/osx/1/otool/
 - Plutil: .plist ファイルをバイナリバージョンと XML バージョンの間で変換できるプログラムです。 - https://www.theiphonewiki.com/wiki/Plutil
 - Weak Classdump: 関数に渡されるクラスのヘッダファイルを生成する Cycript スクリプトです。classdump や dumpdecrypted を使用できない場合やバイナリが暗号化されている場合などにとても便利です。 - https://github.com/limneos/weak_classdump


#### 動的解析および実行時解析

 - bfinject: 任意の dylib を実行中の App Store アプリにロードするツールです。App Store アプリの復号化のサポートが組み込まれており、iSpy と Cycript がバンドルされています。 - https://github.com/BishopFox/bfinject
 - BinaryCookieReader: バイナリ Cookies.binarycookies ファイルからすべてのクッキーをダンプするツールです。 - https://securitylearn.net/wp-content/uploads/tools/iOS/BinaryCookieReader.py
 - Burp Suite Mobile Assistant: 証明書ピンニングをバイパスし、アプリにインジェクトできるツールです。 - https://portswigger.net/burp/help/mobile_testing_using_mobile_assistant.html
 - Cycript: 構文強調表示とタブ補完機能を備えた対話型コンソールを通じて Objective-C および JavaScript 構文をハイブリッドに使用して、開発者が iOS もしくは macOS 上で実行中のアプリケーションを探索および改変できるツールです。 - http://www.cycript.org
 - Frida-cycript: Frida が提供する新しいランタイム Mjølner を有する Cycript のフォークです。これにより frida-cycript は frida-core によりメンテされているすべてのプラットフォームおよびアーキテクチャ上で実行できます。 - https://github.com/nowsecure/frida-cycript
 - Fridpa: iOS アプリケーション (IPA ファイル) にパッチを適用するための自動ラッパースクリプトであり、非脱獄済みデバイスで動作します。 - https://github.com/tanprathan/Fridpa
 - gdb: iOS アプリケーションの実行時解析を行うためのツールです。 - http://cydia.radare.org/debs/
 - idb: iOS ペネトレーションテストおよび研究のための一般的なタスクを簡素化するツールです。 - https://github.com/dmayer/idb
 - Introspy-iOS: iOS アプリケーションが実行時に何をしているかを理解し、潜在的なセキュリティ問題の特定を支援するブラックボックスツールです。 - https://github.com/iSECPartners/Introspy-iOS
 - keychaindumper: iOS デバイスが脱獄された場合に攻撃者が利用可能となるキーチェーンアイテムを確認するためのツールです。 - http://cydia.radare.org/debs/
 - lldb: iOS アプリケーションをデバッグするために使用される Apple の Xcode に付属するデバッガです。 - https://lldb.llvm.org/
 - Needle: バイナリ解析、静的コード解析、実行時操作などの iOS アプリのセキュリティ評価を行うためのモジュラフレームワークです。 - https://github.com/mwrlabs/needle
 - Passionfruit: 完全なウェブベースの GUI を備えたシンプルな iOS アプリブラックボックス評価ツールです。frida.re と vuejs により提供されています。 - https://github.com/chaitin/passionfruit

#### 脱獄検出および SSL ピンニングのバイパス

 - SSL Kill Switch 2: iOS および macOS アプリ内の SSL 証明書検証 (証明書ピンニングを含む) を無効にするブラックボックスツールです。 - https://github.com/nabla-c0d3/ssl-kill-switch2
 - tsProtector: 脱獄検出をバイパスするためのツールです。 - http://cydia.saurik.com/package/kr.typostudio.tsprotector8
 - Xcon: 脱獄検出をバイパスするためのツールです。 - http://cydia.saurik.com/package/com.n00neimp0rtant.xcon/

### ネットワーク傍受および監視用ツール

 - bettercap: セキュリティ研究者やリバースエンジニアに、Wi-Fi, Bluetooth Low Energy, ワイヤレス HID ハイジャック、イーサネットネットワークの偵察および MITM 攻撃のための使いやすいオールインワンソリューションを提供することを目的とした強力なフレームワークです。 - https://www.bettercap.org/
 - Canape: 任意のプロトコル用のネットワークテストツールです。 - https://github.com/ctxis/canape
 - Mallory: モバイルデバイスやアプリケーションのトラフィックを監視および操作するために使用する中間者攻撃 (MiTM) ツールです。 - https://github.com/intrepidusgroup/mallory
 - MITM Relay: SSL および STARTTLS インターセプトをサポートする Burp などを介した非 HTTP プロトコルを傍受および改変するスクリプトです。 - https://github.com/jrmdev/mitm_relay
 - tcpdump: コマンドラインパケットキャプチャユーティリティです。 - https://www.tcpdump.org/
 - Wireshark: オープンソースのパケットアナライザです。 - https://www.wireshark.org/download.html

### 傍受プロキシ

 - Burp Suite: アプリケーションのセキュリティテストを実行するための統合プラットフォームです。 - https://portswigger.net/burp/download.html
 - Charles Proxy: 開発者がマシンとインターネットの間のすべての HTTP および SSL / HTTPS トラフィックを表示することができる HTTP プロキシ / HTTP モニタ / リバースプロキシです。 - https://www.charlesproxy.com
 - Fiddler: HTTP および HTTPS トラフィックをキャプチャしてユーザーが確認するためにログに記録できる HTTP デバッグプロキシサーバーアプリケーションです。 - https://www.telerik.com/fiddler
 - OWASP Zed Attack Proxy (ZAP): ウェブアプリケーションやウェブサービスのセキュリティ脆弱性を自動的に発見するのに役立つフリーのセキュリティツールです。 - https://github.com/zaproxy/zaproxy
 - Proxydroid: Android システム用のグローバルプロキシアプリです。 - https://github.com/madeye/proxydroid

### IDE

 - Android Studio: Google の Android オペレーティングシステム向けの公式の統合開発環境 (IDE) です。JetBrains の IntelliJ IDEA ソフトウェアで構築されており、特に Android 開発向けに設計されています。 - https://developer.android.com/studio/index.html
 - IntelliJ IDEA: コンピュータソフトウェアを開発するための Java IDE です。 - https://www.jetbrains.com/idea/download/
 - Eclipse: Eclipse はコンピュータプログラミングに使用される IDE であり、最も広く使用されている Java IDE です。 - https://eclipse.org/
 - Xcode: iOS, watchOS, tvOS, macOS 用のアプリを作成するための公式の IDE です。 macOS でのみ利用できます。 - https://developer.apple.com/xcode/

### 脆弱なアプリケーション

下記のアプリケーションはトレーニング教材として使用できます。注意：MSTG アプリと Crackmes のみが MSTG プロジェクトでテストおよび保守されています。

#### Android

 - Crackmes: Android アプリのハッキングスキルをテストするためのアプリのセットです。 - https://github.com/OWASP/owasp-mstg/tree/master/Crackmes
 - DVHMA: 意図的に脆弱性を含んでいるハイブリッドモバイルアプリ (Android 向け) です。 - https://github.com/logicalhacking/DVHMA
 - Digitalbank: 2015年に作られた脆弱なアプリで、古い Android プラットフォームで使用できます。 - https://github.com/CyberScions/Digitalbank
 - DIVA Android: 意図的にセキュアではないように設計されたアプリで、2016年に更新されており、13のさまざまな課題を含んでいます。 - https://github.com/payatu/diva-android
 - DodoVulnerableBank: 2015年からのセキュアではない Android アプリです。 - https://github.com/CSPF-Founder/DodoVulnerableBank
 - InsecureBankv2: セキュリティ愛好家や開発者が脆弱なアプリケーションをテストすることにより Android の危険性を知ることができる脆弱な Android アプリです。2018年に更新され、多くの脆弱性を含んでいます。 - https://github.com/dineshshetty/Android-InsecureBankv2
 - MSTG Android app: Java - このドキュメントで説明されているテストケースと同様の脆弱性を持つ脆弱な Android アプリです。 - https://github.com/OWASP/MSTG-Hacking-Playground/releases
 - MSTG Android app: Kotlin - このドキュメントで説明されているテストケースと同様の脆弱性を持つ脆弱な Android アプリです。 - https://github.com/OWASP/MSTG-Hacking-Playground/releases

#### iOS

 - Crackmes: iOS アプリケーションのハッキングスキルをテストするアプリケーションのセットです。 - https://github.com/OWASP/owasp-mstg/tree/master/Crackmes
 - Myriam: iOS セキュリティの課題を持つ脆弱な iOS アプリです。 - https://github.com/GeoSn0w/Myriam
 - DVIA: モバイルセキュリティ愛好家／専門家や学生に iOS ペネトレーションテストスキルをテストするためのプラットフォームを提供する、Objective-C で書かれた脆弱な iOS アプリです。 - http://damnvulnerableiosapp.com/
 - DVIA-v2: 脆弱な iOS アプリです。Swift で書かれ、15以上の脆弱性があります。 - https://github.com/prateek147/DVIA-v2
 - iGoat: iOS 開発者 (iPhone, iPad など) およびモバイルアプリペネトレーションテスト技術者のための楽手ツールとして機能する iOS Objective-C アプリです。WebGoat プロジェクトに触発されたもので、同様の概念的な流れを持っています。 - https://github.com/owasp/igoat
 - iGoat-Swift: オリジナル iGoat プロジェクトの Swift バージョンです。 - https://github.com/owasp/igoat-swift
