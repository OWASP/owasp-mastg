# 扉

## OWASP モバイルセキュリティテストガイドについて

OWASP モバイルセキュリティテストガイド (MSTG) はモバイルアプリのセキュリティをテストするための包括的なマニュアルです。[モバイルアプリケーションセキュリティ検証標準 (MASVS)](https://github.com/OWASP/owasp-masvs "MASVS") に記載される要件を検証するためのプロセスと技法について説明し、完全かつ一貫したセキュリティテストのベースラインを提供します。

OWASP は多くの執筆者、レビュー担当者、編集者がこのガイドの開発に熱心に取り組んでくれたことに感謝しています。モバイルセキュリティテストガイドにコメントや提案がある場合は、[OWASP Mobile Security Project Slack Channel](https://owasp.slack.com/messages/project-mobile_omtg/details/ "OWASP Mobile Security Project Slack Channel") に参加して MASVS や MSTG の議論に参加してください。あなたは [この招待状](https://join.slack.com/t/owasp/shared_invite/enQtNDI5MzgxMDQ2MTAwLTEyNzIzYWQ2NDZiMGIwNmJhYzYxZDJiNTM0ZmZiZmJlY2EwZmMwYjAyNmJjNzQxNzMyMWY4OTk3ZTQ0MzFhMDY "Slack channel sign up") を使用して自分で Slack チャネルにサインアップできます。(招待状の有効期限が切れている場合は PR を開いてください。) 

## 著作権とライセンス

![license](Images/CC-license.png)
Copyright © 2018 The OWASP Foundation. 本書は [Creative Commons Attribution-ShareAlike 4.0 International License](https://creativecommons.org/licenses/by-sa/4.0/) に基づいて公開されています。再使用または配布する場合は、他者に対し本著作物のライセンス条項を明らかにする必要があります。

## 謝辞

**注意**: この寄稿者テーブルは [GitHub contribution statistics](https://github.com/OWASP/owasp-mstg/graphs/contributors "GitHub contribution statistics") に基づいて作成しています。これらの統計情報の詳細については、[GitHub Repository README](https://github.com/OWASP/owasp-mstg/blob/master/README.md "GitHub Repository README") を参照ください。手動でテーブルを更新しますので、あなたがすぐにリストに載らなくてもあわてないでください。

### 執筆者

#### Bernhard Mueller

Bernhard はあらゆる種類のシステムをハックする才能を持つサイバーセキュリティの専門家です。業界で10年以上にわたり、MS SQL Server, Adobe Flash Player, IBM Director, Cisco VOIP, ModSecurity などのソフトウェアに対するゼロデイエクスプロイトを多数公表しています。それに名前をつけることができても、おそらく少なくとも一度はそれを破棄しているでしょう。BlackHat USA は Pwnie Award for Best Research でモバイルセキュリティの先駆的な取り組みを賞賛しました。

#### Sven Schleier

Sven は経験豊かなウェブおよびモバイルのペネトレーションテスト技術者であり、歴史上有名な Flash アプリケーションからプログレッシブモバイルアプリまでのすべてを評価しています。彼はセキュリティエンジニアでもあり、SDLC の中でエンドツーエンドで多くのプロジェクトをサポートし「セキュリティを構築」しています。彼はローカルおよびインターナショナルの会議やカンファレンスで講演し、ウェブアプリケーションやモバイルアプリのセキュリティに関するハンズオンワークショップを行っています。

#### Jeroen Willemsen

Jeroen は Xebia の主要なセキュリティアーキテクトであり、モバイルセキュリティとリスク管理に対する情熱を持っています。彼はセキュリティコーチ、セキュリティエンジニアとして企業をサポートしておりフルスタックの開発者としてどんな仕事でもこなします。彼は、セキュリティ問題からプログラミングの課題まで、技術的な問題を議論するのが大好きです。

### 共同執筆者

共同執筆者は一貫して質の高いコンテンツを寄稿しており、GitHub リポジトリに少なくとも 2,000 件の追加が記録されています。

#### Romuald Szkudlarek

Romuald はウェブ、モバイル、IoT、クラウドの分野で 15 年以上の経験を持つ情熱的なサイバーセキュリティおよびプライバシーの専門家です。彼のキャリアの中で、彼はソフトウェアとセキュリティの分野を進歩させることを目標に、さまざまなプロジェクトに余暇をささげていました。彼はさまざまな機関で定期的に指導しています。彼は CISSP, CCSP, CSSLP, CEH の資格を保持しています。

### 主寄稿者

主寄稿者は一貫して質の高いコンテンツを寄稿しており、GitHub リポジトリに少なくとも 500 件の追加が記録されています。

- Pawel Rzepa
- Francesco Stillavato
- Henry Hoggard
- Andreas Happe
- Kyle Benac
- Alexander Anthuk
- Wen Bin Kong
- Abdessamad Temmar
- Bolot Kerimbaev
- Cláudio André
- Slawomir Kosowski

### 寄稿者

寄稿者は質の高いコンテンツを寄稿しており、GitHub リポジトリに少なくとも 50 件の追加が記録されています。

Jin Kung Ong, Koki Takeyama, Sjoerd Langkemper, Gerhard Wagner, Michael Helwig, Pece Milosev, Jeroen Beckers, Ryan Teoh, Denis Pilipchuk, Dharshin De Silva, Anatoly Rosencrantz, Abhinav Sejpal, Dominique Righetto, José Carlos Andreu, Raul Siles, Daniel Ramirez Martin, Yogesh Sharma, Enrico Verzegnassi, Nick Epson, Emil Tostrup, Prathan Phongthiproek, Tom Welch, Luander Ribeiro, Heaven L. Hodges, Carlos Holguera, Dario Incalza, Akanksha Bana, Oguzhan Topgul, Vikas Gupta, David Fern, Pishu Mahtani, Anuruddha E.

### レビュー担当者

レビュー担当者は GitHub issues および pull request コメントを通して有用なフィードバックを一貫して提供しています。

- Sjoerd Langkemper
- Anant Shrivastava

### 編集者

- Heaven Hodges
- Caitlin Andrews
- Nick Epson
- Anita Diamond
- Anna Szkudlarek

### その他

他の多くの寄稿者が単一の単語や文章など (追加数が 50 件未満) の少量のコンテンツをコミットしています。寄稿者の完全なリストは [GitHub](https://github.com/OWASP/owasp-mstg/graphs/contributors "contributors") にあります。

## スポンサー

MASVS と MSTG のいずれもコミュニティにより無償奉仕で作成および維持されていますが、時にはいくらかの外的支援が必要となることもあります。したがって、テクニカルエディタを雇うことができる資金を提供したスポンサーに感謝します。彼らのスポンサーシップは MASVS や MSTG の内容にいかなる形であれ影響を与えないことに注意します。スポンサーシップパッケージは [OWASP Project Wiki](https://www.owasp.org/index.php/OWASP_Mobile_Security_Testing_Guide#tab=Sponsorship_Packages "OWASP Mobile Security Testing Guide Sponsorship Packages") に記載されています。

### 名誉後援者

[![NowSecure](Images/Sponsors/NowSecure_logo.png)](https://www.nowsecure.com/ "NowSecure")


### 旧版

モバイルセキュリティテストガイドは2015年に Milan Singh Thakur によって開始されました。元のドキュメントは Google ドライブでホストされていました。ガイド開発は2016年10月に GitHub に移されました。

**OWASP MSTG "Beta 2" (Google Doc)**

| 執筆者 | レビュー担当者 | 主寄稿者 |
| --- | --- | --- |
| Milan Singh Thakur, Abhinav Sejpal, Blessen Thomas, Dennis Titze, Davide Cioccia, Pragati Singh, Mohammad Hamed Dadpour, David Fern, Mirza Ali, Rahil Parikh, Anant Shrivastava, Stephen Corbiaux, Ryan Dewhurst, Anto Joseph, Bao Lee, Shiv Patel, Nutan Kumar Panda, Julian Schütte, Stephanie Vanroelen, Bernard Wagner, Gerhard Wagner, Javier Dominguez | Andrew Muller, Jonathan Carter, Stephanie Vanroelen, Milan Singh Thakur  | Jim Manico, Paco Hope, Pragati Singh, Yair Amit, Amin Lalji, OWASP Mobile Team|

**OWASP MSTG "Beta 1" (Google Doc)**

| 執筆者 | レビュー担当者 | 主寄稿者 |
| --- | --- | --- |
| Milan Singh Thakur, Abhinav Sejpal, Pragati Singh, Mohammad Hamed Dadpour, David Fern, Mirza Ali, Rahil Parikh | Andrew Muller, Jonathan Carter | Jim Manico, Paco Hope, Yair Amit, Amin Lalji, OWASP Mobile Team  |
