## テストツール

セキュリティテストを実行するためにさまざまなツールが利用できます。リクエストやレスポンスを操作したり、アプリを逆コンパイルしたり、実行中のアプリの挙動を調査したり、テストケースを自動化したりできます。

### モバイルアプリケーションセキュリティテストディストリビューション

- [Appie](https://manifestsecurity.com/appie/ "Appie") - Android ペンテスト向けのポータブルなソフトウェアパッケージで、既存の仮想マシンに代わる素晴らしいツールです。
- [Androl4b](https://github.com/sh4hin/Androl4b "Androl4b") - Android アプリケーションの評価、リバースエンジニアリング、マルウェア解析のための仮想マシンです。
- [Android Tamer](https://androidtamer.com/ "Android Tamer") - Android Tamer は Android セキュリティ専門家向けの Debian ベースの仮想／ライブプラットフォームです。
- [AppUse](https://appsec-labs.com/AppUse/ "Appuse") - AppUse は AppSec Labs により開発された仮想マシンです。
- [Mobisec](https://sourceforge.net/projects/mobisec/ "Mobisec") - モバイルセキュリティテストのライブ環境です。
- [Santoku](https://santoku-linux.com/ "Santoku") - Santoku は OS であり、スタンドアロンのオペレーティングシステムとして VM の外部で実行できます。
- [Mobile Security Toolchain](https://github.com/xebia/mobilehacktools "Mobile Security Toolchain") - Mac OSX を実行しているマシンで Android と iOS の両方でこのセクションで説明したツールの多くをインストールするために使用されるプロジェクトです。このプロジェクトは Ansible を介してツールをインストールします。
- [Vezir Project](https://github.com/oguzhantopgul/Vezir-Project "Vezir Project") - モバイルアプリケーションのペンテストとマルウェア解析環境です。

### 静的ソースコード解析

- [Checkmarx](https://www.checkmarx.com/technology/static-code-analysis-sca/ "Checkmarx") - 静的ソースコードスキャナであり、Android および iOS 用のソースコードもスキャンします。
- [Fortify](https://saas.hpe.com/en-us/software/fortify-on-demand/mobile-security "Fortify") - 静的ソースコードスキャナであり、Android および iOS 用のソースコードもスキャンします。
- [Veracode](https://www.veracode.com/products/binary-static-analysis-sast "Veracode Static Analysis") - iOS および Android バイナリの静的解析です。

### オールインワンモバイルセキュリティフレームワーク

- [Appmon](https://github.com/dpnishant/appmon/ "Appmon") - AppMon はネイティブ macOS, iOS, android アプリのシステム API コールを監視および改竄するための自動化フレームワークです。
- [Mobile Security Framework - MobSF](https://github.com/ajinabraham/Mobile-Security-Framework-MobSF "Mobile Security Framework - MobSF") - Mobile Security Framework は静的解析および動的解析を実行できるインテリジェントでオールインワンのオープンソースモバイルアプリケーション (Android/iOS) 自動ペネトレーションテストフレームワークです。
- [Needle](https://github.com/mwrlabs/needle "Needle") - Needle はオープンソースのモジュラーフレームワークであり、バイナリ解析、静的コード解析、Cycript や Frida フッキングを使用した実行時操作などの iOS アプリのセキュリティ評価実施のプロセスを効率化します。
- [objection](https://github.com/sensepost/objection "objection") - objection は iOS および android の両方に対応し、Frida を使用することにより、脱獄やルート化デバイスを必要としない実行時モバイルセキュリティ評価フレームワークです。

### Android 用ツール

#### リバースエンジニアリングおよび静的解析

- [Androguard](https://github.com/androguard/androguard "Androguard") - Androguard は python ベースのツールで、android アプリの逆アセンブルや逆コンパイルに使用できます。
- [Android Debug Bridge - adb](https://developer.android.com/studio/command-line/adb.html "Android Debug Bridge") - Android Debug Bridge (adb) はエミュレータインスタンスや接続された Android デバイスと通信するための多彩なコマンドラインツールです。
- [APKInspector](https://github.com/honeynet/apkinspector/ "APKInspector") - APKinspector は Android アプリケーションを解析するアナリスト向けの強力な GUI ツールです。
- [APKTool](https://ibotpeaches.github.io/Apktool/ "APKTool") - サードパーティ製でクローズなバイナリ Android アプリをリバースエンジニアリングするためのツールです。リソースをほぼ元の形にデコードし、改変後に再構築することができます。
- [android-classyshark](https://github.com/google/android-classyshark "android-classyshark") - ClassyShark は Android 開発者向けのスタンドアロンのバイナリインスペクションツールです。
- [Sign](https://github.com/appium/sign "Sign") - Sign.jar は自動的に Android テスト証明書で apk に署名します。
- [Jadx](https://github.com/skylot/jadx "Jadx") - Dex から Java への逆コンパイラです。Android Dex および Apk ファイルから Java ソースコードを生成するコマンドラインおよび GUI ツールです。
- [Oat2dex](https://github.com/testwhat/SmaliEx "Oat2dex") - .oat ファイルから .dex ファイルに変換するためのツールです。
- [FindBugs](http://findbugs.sourceforge.net "FindBugs") - Java 用の静的解析ツールです。
- [FindSecurityBugs](https://find-sec-bugs.github.io "FindSecurityBugs") - FindSecurityBugs は FindBugs の拡張機能であり、Java アプリケーション向けのセキュリティルールを含んでいます。
- [Qark](https://github.com/linkedin/qark "Qark") - このツールは Android アプリケーション脆弱性に関連するいくつかのセキュリティをソースコードかパッケージ化された APK のいずれかで検索するように設計されています。
- [SUPER](https://github.com/SUPERAndroidAnalyzer/super "SUPER") - SUPER は Windows, MacOS X, Linux で使用できるコマンドラインアプリケーションで、.apk ファイルを検索して脆弱性を探します。APK を展開し、脆弱性を検出するための一連のルールを適用することでこれを行います。
- [AndroBugs](https://github.com/AndroBugs/AndroBugs_Framework "AndroBugs") - AndroBugs フレームワークは開発者やハッカーが Android アプリケーションの潜在的なセキュリティ脆弱性を発見するのに役立つ効率的な Android 脆弱性スキャナです。Windows にインストールする必要はありません。
- [Simplify](https://github.com/CalebFenton/simplify "Simplify") - Classes.dex 内の android パッケージを逆難読化するツールです。Dex2jar や JD-GUI を使用して dex ファイルの内容を抽出できます。
- [ClassNameDeobfuscator](https://github.com/HamiltonianCycle/ClassNameDeobfuscator "ClassNameDeobfuscator") - apktool により生成される .smali ファイルを解析して .source アノテーション行を抽出するシンプルなスクリプトです。
- [Android backup extractor](https://github.com/nelenkov/android-backup-extractor "Android backup extractor") - adb backup (ICS 以降) で作成された Android バックアップを抽出および再パックするユーティリティです。主に AOSP の BackupManagerService.java をベースとしています。
- [VisualCodeGrepper](https://sourceforge.net/projects/visualcodegrepp/ "VisualCodeGrepper") - Java などのいくつかのプログラミング言語向けの静的コード解析ツールです。
- [ByteCodeViewer](https://bytecodeviewer.com/ "ByteCodeViewer") - 五つの異なる Java 逆コンパイラ、二つのバイトコードエディタ、Java コンパイラ、プラグイン、検索。Class, JAR, Android APK などからのロードをサポートしています。

#### 動的解析および実行時解析

- [Cydia Substrate](http://www.cydiasubstrate.com) - Android 向けの Cydia Substrate を使用すると、開発者はターゲットプロセスのメモリにインジェクトされる Substrate extension で既存のソフトウェアを改造することができます。
- [Xposed Framework](https://forum.xda-developers.com/xposed/xposed-installer-versions-changelog-t2714053) - Xposed framework を使用すると、Android アプリケーションパッケージ (APK) の改変や再フラッシュを行わずに、実行時にシステムやアプリケーションのアスペクトや動作を変更できます。
- [logcat-color](https://github.com/marshall/logcat-color) - Android SDK の adb logcat コマンドに代わるカラフルで高度な設定が可能なツールです。
- [Inspeckage](https://github.com/ac-pm/Inspeckage) - Inspeckage は Android アプリケーションの動的解析を提供するために開発されたツールです。Android API の関数にフックを適用することで、Inspeckage は Android アプリケーションが実行時に何をしているのかを理解するのに役立ちます。
- [Frida](https://www.frida.re) - このツールキットはクライアントサーバーモデルを使用して動作し、Android の上だけでなく iOS, Windows, Mac の上でも実行中のプロセスにインジェクトすることができます。
- [Diff-GUI](https://github.com/antojoseph/diff-gui) - 利用可能なモジュールで計装を開始し、ネイティブでフックし、Frida を使用して JavaScript をインジェクトする Web フレームワークです。
- [AndBug](https://github.com/swdunlop/AndBug) - AndBug は Android プラットフォーム Dalvik 仮想マシンを対象とするリバースエンジニアおよび開発者向けのデバッガです。
- [Cydia Substrate: Introspy-Android](https://github.com/iSECPartners/Introspy-Android) - Android アプリケーションが実行時に何をしているかを理解し、潜在的なセキュリティ問題の特定を支援するブラックボックスツールです。
- [Drozer](https://www.mwrinfosecurity.com/products/drozer/) - Drozer はアプリの役割を想定し、Dalvik VM と他のアプリの IPC エンドポイントや基礎をなす OS とのやり取りを行うことで、アプリやデバイスのセキュリティ脆弱性を検索することができます。
- [VirtualHook](https://github.com/rk700/VirtualHook) - VirtualHook は Android ART(>=5.0) のアプリケーション用のフッキングツールです。VirtualApp をベースにしており、フックを挿入するためにルート権限は必要ありません。
- [NowSecure](https://nowsecure.com/) - Frida と Radare2 の作成者によりもたらされた Android と iOS モバイルアプリの自動の動的および静的解析で、ネットワーク中間者攻撃や API レベルのセキュリティ解析を含みます。

#### ルート検出と証明書ピンニングのバイパス

- [Xposed Module: Just Trust Me](https://github.com/Fuzion24/JustTrustMe "Xposed Module: Just Trust Me") - SSL 証明書ピンニングをバイパスする Xposed モジュールです。
- [Xposed Module: SSLUnpinning](https://github.com/ac-pm/SSLUnpinning_Xposed "Xposed Module: SSLUnpinning") - SSL 証明書検証 (証明書ピンニング) をバイパスする Android Xposed モジュールです。
- [Cydia Substrate Module: Android SSL Trust Killer](https://github.com/iSECPartners/Android-SSL-TrustKiller "Cydia Substrate Module: Android SSL Trust Killer") - デバイス上で動作するほとんどのアプリケーションの SSL 証明書ピンニングをバイパスするブラックボックスツールです。
- [Cydia Substrate Module: RootCoak Plus](https://github.com/devadvance/rootcloakplus "Cydia Substrate Module: RootCoak Plus") - 一般的に知られているルートの兆候に対するルートチェックにパッチを適用します。
- [Android-ssl-bypass](https://github.com/iSECPartners/android-ssl-bypass "Android-ssl-bypass") - 他のデバッグタスクと同様に、証明書ピンニングが実装されている場合でも SSL をバイパスすることに使用できる Android デバッグツールです。このツールは対話型コンソールとして実行します。
- [Frida CodeShare](https://codeshare.frida.re/ "Frida CodeShare") - Frida CodeShare プロジェクトは世界各地の開発者が、Frida を新たな革新的な方法でその限界を押し進めるという、一つの目標に向かって協力しています。

#### セキュリティライブラリ

- [Java AES Crypto](https://github.com/tozny/java-aes-crypto "Java AES Crypto") - 文字列を暗号化および復号化するためのシンプルな Android クラスです。ほとんどのクラスが被っている古くからの間違いを避けることを目指しています。
- [Proguard](https://www.guardsquare.com/en/products/proguard "Proguard") - ProGuard はフリーの Java クラスファイル圧縮ツール、オプティマイザ、難読化ツール、および事前検証ツールです。未使用のクラス、フィールド、メソッド、属性を検出して削除します。
- [SQL Cipher](https://www.zetetic.net/sqlcipher/sqlcipher-for-android/ "SQL Cipher") - SQLCipher は SQLite のオープンソース拡張であり、データベースファイルの等価的な 256 ビット AES 暗号化を提供します。
- [Secure Preferences](https://github.com/scottyab/secure-preferences "Secure Preferences") - Android 共有プリファレンスラッパーであり、共有プリファレンスのキーと値を暗号化します。
- [Trusted Intents](https://github.com/guardianproject/TrustedIntents "Trusted Intents") - Android アプリ間の柔軟で信頼性の高いやり取りのためのライブラリです。
- [Capillary](https://github.com/google/capillary "Capillary") - Capillary は Java ベースのアプリケーションサーバーから Android クライアントへのエンドツーエンドの暗号化プッシュメッセージの送信を簡素化するライブラリです。




### iOS 用ツール

#### iDevice 上のファイルシステムへのアクセス

- [FileZilla](https://filezilla-project.org/download.php?show_all=1 "FireZilla") -  FTP, SFTP, FTPS (FTP over SSL/TLS) をサポートしています。
- [Cyberduck](https://cyberduck.io "Cyberduck") - Mac および Windows 向けの Libre FTP, SFTP, WebDAV, S3, Azure & OpenStack Swift ブラウザです。
- [itunnel](https://code.google.com/p/iphonetunnel-usbmuxconnectbyport/downloads/list "itunnel") -  USB 経由で SSH を転送するために使用します。
- [iFunbox](http://www.i-funbox.com "iFunbox") - iPhone, iPad, iPod Touch 向けのファイルおよびアプリ管理ツールです。
- [iProxy](https://github.com/tcurdt/iProxy "iProxy") - ラップトップを iPhone に接続してウェブをサーフィンしましょう。

#### リバースエンジニアリングおよび静的解析

- [otool](https://www.unix.com/man-page/osx/1/otool/ "otool") - otool コマンドはオブジェクトファイルやライブラリの指定された箇所を表示します。
- [Clutch](http://cydia.radare.org/ "Clutch") - アプリケーションを解読し、バイナリや .ipa ファイルに指定された bundleID をダンプします。
- [Dumpdecrypted](https://github.com/stefanesser/dumpdecrypted "Dumpdecrypted") -  暗号化された iPhone アプリケーションから復号された mach-o ファイルをメモリからディスクにダンプします。このツールはセキュリティ研究者が暗号化の中身を具体的に見ることができるようにするために必要となります。
- [class-dump](http://stevenygard.com/projects/class-dump/ "class-dump") - Mach-O ファイルに格納されている Objective-C ランタイム情報を調べるためのコマンドラインユーティリティです。
- [Flex2](http://cydia.saurik.com/package/com.fuyuchi.flex2/ "Flex2") - Flex はアプリを改変し動作を変更する力を与えます。
- [Weak Classdump](https://github.com/limneos/weak_classdump "Weak Classdump") - 関数に渡されるクラスのヘッダファイルを生成する Cycript スクリプトです。classdump や dumpdecrypted ができない場合やバイナリが暗号化されている場合などにとても便利です。
- [IDA Pro](https://www.hex-rays.com/products/ida/index.shtml "IDA Pro") - IDA は Windows, Linux, Mac OS X でホストされているマルチプロセッサ逆アセンブラおよびデバッガであり、すべてを記述するのは難しいほどの多くの機能を提供しています。
- [HopperApp](https://www.hopperapp.com/ "HopperApp") - Hopper は OS X および Linux 用のリバースエンジニアリングツールで、32/64 ビット Intel Mac, Linux, Windows, iOS 実行可能ファイルを逆アセンブル、逆コンパイル、デバッグすることができます。
- [hopperscripts](https://github.com/Januzellij/hopperscripts "hopperscripts") - Hopperscripts を使用して、HopperApp の Swift 関数名をデマングルできます。
- [Radare2](https://www.radare.org/r/ "Radare2") - Radare2 は Unix ライクなリバースエンジニアリングフレームワークおよびコマンドラインツールです。
- [iRET](https://www.veracode.com/iret-ios-reverse-engineering-toolkit "iRET") - iOS Reverse Engineering Toolkit は iOS ペネトレーションテストに関連する多くの一般的なタスクを自動化するためのツールキットです。
- [Plutil](https://www.theiphonewiki.com/wiki/Plutil "Plutil") - plutil は .plist ファイルをバイナリバージョンと XML バージョンの間で変換できるプログラムです。

#### 動的解析および実行時解析

- [cycript](http://www.cycript.org "cycript") - Cycript を使用すると、開発者は構文強調表示とタブ補完機能を備えた対話型コンソールを通じて Objective-C++ および JavaScript 構文をハイブリッドに使用して iOS もしくは Mac OS X 上で実行中のアプリケーションを探索および改変できます。
- [Frida-cycript](https://github.com/nowsecure/frida-cycript "Frida-cycript") - これは Cycript のフォークで、ランタイムを Frida が提供する新しいランタイム Mjølner に置き換えました。これにより frida-cycript は frida-core によりメンテされているすべてのプラットフォームおよびアーキテクチャ上で実行できます。
- [Fridpa](https://github.com/tanprathan/Fridpa "Fridpa") - iOS アプリケーション (IPA ファイル) にパッチを適用するための自動ラッパースクリプトであり、非脱獄済みデバイスで動作します。
- [bfinject](https://github.com/BishopFox/bfinject "bfinject") - bfinject は任意の dylib を実行中の App Store アプリにロードします。これには App Store アプリの復号化のサポートが組み込まれており、iSpy と Cycript がバンドルされています。
- [iNalyzer](https://appsec-labs.com/cydia/ "iNalyzer") - AppSec Labs iNalyzer はパラメータやメソッドを改竄して iOS アプリケーションを操作するためのフレームワークです。
- [Passionfruit](https://github.com/chaitin/passionfruit "Passionfruit") - 完全なウェブベースの GUI を備えたシンプルな iOS アプリブラックボックス評価ツールです。frida.re と vuejs により提供されています。
- [idb](https://github.com/dmayer/idb "idb") - idb は iOS ペネトレーションテストおよび研究のための一般的なタスクを簡素化するツールです。
- [snoop-it](http://cydia.radare.org/ "snoop-it") - iOS アプリのセキュリティ評価および動的解析を支援するツールです。
- [Introspy-iOS](https://github.com/iSECPartners/Introspy-iOS "Introspy-iOS") - iOS アプリケーションが実行時に何をしているかを理解し、潜在的なセキュリティ問題の特定を支援するブラックボックスツールです。
- [gdb](http://cydia.radare.org/ "gdb") - iOS アプリケーションの実行時解析を行うためのツールです。
- [lldb](https://lldb.llvm.org/ "lldb") - Apple の Xcode に付属する LLDB デバッガは iOS アプリケーションをデバッグするために使用されます。
- [Apple configurator 2](https://itunes.apple.com/us/app/apple-configurator-2/id1037126344?mt=12 "Apple configurator 2") - iDevice のライブシステムログを表示するために使用できるユーティリティです。
- [keychaindumper](http://cydia.radare.org/ "keychaindumper") - iOS デバイスが脱獄された場合に攻撃者が利用可能となるキーチェーンアイテムを確認するためのツールです。
- [BinaryCookieReader](https://securitylearn.net/wp-content/uploads/tools/iOS/BinaryCookieReader.py "BinaryCookieReader") - バイナリ Cookies.binarycookies ファイルからすべてのクッキーをダンプするツールです。
- [Burp Suite Mobile Assistant](https://portswigger.net/burp/help/mobile_testing_using_mobile_assistant.html "Burp Suite Mobile Assistant") - 証明書ピンニングをバイパスし、アプリにインジェクトできるツールです。


#### ルート検出および SSL ピンニングのバイパス

- [SSL Kill Switch 2](https://github.com/nabla-c0d3/ssl-kill-switch2 "SSL Kill Switch 2") - iOS および OS X アプリ内の SSL 証明書検証 (証明書ピンニングを含む) を無効にするブラックボックスツールです。
- [TrustKit](https://github.com/datatheorem/TrustKit "TrustKit") - TrustKit は任意の iOS 10+, macOS 10.10+, tvOS 10+, watchOS 3+ アプリで SSL 公開鍵ピンニングとレポーティングをデプロイするための使いやすい API を提供します。Swift と Objective-C アプリの両方をサポートしています。
- [iOS TrustMe](https://github.com/intrepidusgroup/trustme "iOS TrustMe") - iOS デバイスの証明書の信頼チェックを無効にします。
- [Xcon](http://cydia.saurik.com/package/com.n00neimp0rtant.xcon/ "Xcon") - 脱獄検出をバイパスするためのツールです。
- [tsProtector](http://cydia.saurik.com/package/kr.typostudio.tsprotector8 "tsProtector 8") - 脱獄検出をバイパスするためのもうひとつのツールです。
- [Frida CodeShare](https://codeshare.frida.re/ "Frida CodeShare") - Frida CodeShare プロジェクトは世界各地の開発者が、Frida を新たな革新的な方法でその限界を押し進めるという、一つの目標に向かって協力しています。

#### セキュリティライブラリ
- [OWASP iMAS](http://project-imas.github.io/ "OWASP iMAS") - iMAS はオープンソース iOS セキュリティコントロールに焦点を当てた MITRE 社の共同研究プロジェクトです。

### ネットワーク傍受および監視用ツール

- [Tcpdump](https://www.androidtcpdump.com "TCPDump") - コマンドラインパケットキャプチャユーティリティです。
- [Wireshark](https://www.wireshark.org/download.html "WireShark") - オープンソースのパケットアナライザです。
- [Canape](https://github.com/ctxis/canape "Canape") - 任意のプロトコル用のネットワークテストツールです。
- [Mallory](https://intrepidusgroup.com/insight/mallory/ "Mallory") - モバイルデバイスやアプリケーションのトラフィックを監視および操作するために使用する中間者攻撃 (MiTM) ツールです。

### 傍受プロキシ

- [Burp Suite](https://portswigger.net/burp/download.html "Burp Suite") - Burp Suite はアプリケーションのセキュリティテストを実行するための統合プラットフォームです。
- [OWASP ZAP](https://github.com/zaproxy/zaproxy "OWASP ZAP") - OWASP Zed Attack Proxy (ZAP) はウェブアプリケーションやウェブサービスのセキュリティ脆弱性を自動的に発見するのに役立つフリーのセキュリティツールです。
- [Fiddler](https://www.telerik.com/fiddler "Fiddler") - Fiddler は HTTP および HTTPS トラフィックをキャプチャしてユーザーが確認するためにログに記録できる HTTP デバッグプロキシサーバーアプリケーションです。また、Fiddler は送受信時のトラブルシューティングを行うために HTTP トラフィックの改変にも使用できます。
- [Charles Proxy](https://www.charlesproxy.com "Charles Proxy") - 開発者がマシンとインターネットの間のすべての HTTP および SSL / HTTPS トラフィックを表示することができる HTTP プロキシ / HTTP モニタ / リバースプロキシです。
- [Proxydroid](https://github.com/madeye/proxydroid) - Android システム用のグローバルプロキシアプリです。

### IDE

- [Android Studio](https://developer.android.com/studio/index.html "Android Studio") - Android Studio は Google の Android オペレーティングシステム向けの公式の統合開発環境 (IDE) です。JetBrains の IntelliJ IDEA で構築されており、特に Android 開発向けに設計されています。
- [IntelliJ](https://www.jetbrains.com/idea/download/ "InteliJ") - IntelliJ IDEA はコンピュータソフトウェアを開発するための Java 統合開発環境 (IDE) です。
- [Eclipse](https://eclipse.org/ "Eclipse") - Eclipse はコンピュータプログラミングに使用される統合開発環境 (IDE) であり、最も広く使用されている Java IDE です。
- [Xcode](https://developer.apple.com/xcode/ "XCode") - Xcode は iOS, watchOS, tvOS, macOS 用のアプリを作成するための macOS 専用の統合開発環境 (IDE) です。


### 脆弱なアプリケーション
下記のアプリケーションはトレーニング教材として使用できます。

#### Android
- [DVHMA](https://github.com/logicalhacking/DVHMA "Damn Vulnerable Hybrid Mobile App") - 意図的に脆弱性を含んでいるハイブリッドモバイルアプリ (Android 向け) です。
- [Crackmes](https://github.com/OWASP/owasp-mstg/tree/master/Crackmes "Crackmes and license check") - Android アプリのハッキングスキルをテストするためのアプリケーションのセットです。
- [OMTG Android app](https://github.com/OWASP/MSTG-Hacking-Playground) - このドキュメントで説明されているテストケースと同様の脆弱性を持つ脆弱な Android アプリです。
- [Digitalbank](https://github.com/CyberScions/Digitalbank "Android Digital Bank Vulnerable Mobile App") - 2015年に作られた脆弱なアプリで、古い Android プラットフォームで使用できます。注：執筆者はこれをテストしていません。
- [DIVA Android](https://github.com/payatu/diva-android "Damn insecure and vulnerable App") - 意図的にセキュアではないように設計されたアプリで、2016年に更新されており、13のさまざまな課題を含んでいます。注：執筆者はこれをテストしていません。
- [InsecureBankv2](https://github.com/dineshshetty/Android-InsecureBankv2 "Insecure Bank V2") - セキュリティ愛好家や開発者がこの脆弱なアプリケーションをテストすることにより Android の危険性を知ることができます。2018年に更新され、多くの脆弱性を含んでいます。
- [DodoVulnerableBank](https://github.com/CSPF-Founder/DodoVulnerableBank "Dodo Vulnerable Bank") - 2015年のセキュアではない Android アプリ。注：執筆者はこれをテストしていません。



#### iOS

- [Crackmes](https://github.com/OWASP/owasp-mstg/tree/master/Crackmes "Crackmes and license check") - iOS アプリケーションのハッキングスキルをテストするアプリケーションのセットです。
- [Myriam](https://github.com/GeoSn0w/Myriam "Myriam iOS Security App") - iOS セキュリティの課題を持つ脆弱な iOS アプリです。
- [DVIA](https://github.com/prateek147/DVIA "Damn Vulnerable iOS App") - 脆弱な iOS アプリです。一連の脆弱性を持ち Objective-C で書かれています。追加のレッスンが [プロジェクトのウェブサイト](http://damnvulnerableiosapp.com/ "DVIA project website") にあります。
- [DVIA-v2](https://github.com/prateek147/DVIA-v2 "Damn Vulnerable iOS App v2") - 脆弱な iOS アプリです。Swift で書かれ、15以上の脆弱性があります。
