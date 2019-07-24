## Разворачивание тестовой среды для приложений iOS

В предыдущей главе мы предоставили обзор платформы iOS и описали структуру приложений iOS. В этой главе мы расскажем о базовых процессах и методах, которые вы можете использовать для тестирования приложений iOS для поиска уязвимостей безопасности. Эти процессы являются основой для проверок случаев, описанных в следующих главах.

В отличие от эмулятора Android, который полностью эмулирует аппаратное обеспечение реального Android устройства, iOS SDK симулятор предлагает более высокий уровень *симуляции* устройства iOS. Самое главное, что двоичные файлы эмулятора скомпилированы в код x86 вместо кода ARM. Приложения, скомпилированные для реального устройства, не запускаются на симуляторе, что делает симулятор бесполезным для анализа blackbox и обратного проектирования.

Ниже приведен самый простой набор для осуществления тестирования приложений для iOS:

- ноутбук с правами администратора
- сеть Wi-Fi, которая не блокирует трафик клиент-клиент; альтернатива - мультиплексирование USB
- по крайней мере одно устройство iOS с джейлбрейком (желаемой версии iOS)
- Burp Suite или другой инструмент прокси перехвата

Хотя вы можете использовать Linux или Windows для тестирования, вы обнаружите, что многие задачи усложнены или невозможны на этих платформах. Кроме того, среда разработки Xcode и SDK iOS доступны только на macOS. Это означает, что вы определенно захотите работать на Mac для анализа исходного кода и отладки (это также упрощает тестирование blackbox).

### Джейлбрейк устройства iOS

У вас должен быть взломанный iPhone или iPad для запуска тестов. Эти устройства позволяют осуществлять root-доступ и установку инструментария, делая процесс тестирования безопасности более простым. Если у вас нет доступа к джейлбрейк-устройству, вы можете применить обходные пути, описанные ниже в этой главе, но будьте готовы к сложностям.

iOS jailbreaking часто сравнивается с Android rooting, но процесс на самом деле совсем другой. Чтобы объяснить разницу, мы сначала рассмотрим концепции «rooting» и «flashing» на Android.

- **Rooting**: Обычно это связано с установкой бинарного `su` в системе или заменой всей системы на пользовательский образ, уже имеющий права root. Эксплойтам не требуется получение доступа root до тех пор, пока доступен загрузчик.
- **Flashing custom ROMs**: Это позволяет вам заменить ОС, запущенную на устройстве после разблокировки загрузчика. Загрузчику может потребоваться эксплойт, чтобы разблокировать его.

На устройствах iOS загрузка пользовательского образа(flashing custom ROM) невозможно, потому что загрузчик iOS позволяет загружать и дампить образы, подписанные Apple. Вот почему даже официальные образы iOS не могут быть установлены, если они не подписаны Apple, и это делает понижение версии(downgrade) iOS доступным только до тех пор, пока предыдущая версия iOS все еще подписана.

Цель джейлбрейка - отключить защиту iOS(в частности, механизмы подписи кода Apple), чтобы на устройстве мог запускаться произвольный неподписанный код. Слово «джейлбрейк» - это разговорная ссылка на инструменты «все-в-одном», которые автоматизируют процесс джейлбрейка.

Cydia - это альтернативный магазин приложений, разработанный Jay Freeman (он же «saurik») для взломанных устройств. Он предоставляет графический интерфейс пользователя и версию Advanced Packaging Tool (APT). Вы можете легко получить доступ ко многим «несанкционированным» пакетам приложений через Cydia. Большинство джейлбрейков автоматически устанавливают Cydia.

Задача разработки джейлбрейка для текущей версии iOS непроста. В качестве тестировщика безопасности, Вы, скорее всего, захотите использовать общедоступные инструменты для джейлбрейка. Тем не менее, мы рекомендуем изучить методы, которые были использованы для джейлбрейка различных версий iOS - вы столкнетесь со многими интересными эксплойтами и много узнаете о внутренних функциях ОС. Например, Pangu9 для iOS 9.x [использует не менее пяти уязвимостей] (https://www.theiphonewiki.com/wiki/Jailbreak_Exploits "Jailbreak Exploits"), включая ошибку ядра - использование после высвобождения (CVE-2015- 6794) и уязвимость доступа к файловой системе в приложении «Фотографии» (CVE-2015-7037).

#### Преимущества джейлбрейка

Конечные пользователи часто делают джейлбрейк своих устройств, чтобы кастомизировать внешний вид системы iOS, добавить новые функции и установить сторонние приложения из неофициальных магазинов приложений. Однако для тестироващика безопасности, джейлбрейк iOS-устройства имеет еще больше преимуществ. Они включают, но не ограничиваются следующими:

- root-доступ к файловой системе
- возможность выполнения приложений, которые не были подписаны Apple(которые включают в себя множество средств безопасности)
- неограниченная отладка и динамический анализ
- доступ к среде выполнения Objective-C

#### Типы джейлбрейка

Есть *tethered*, *semi-tethered*, *semi-untethered* и *untethered* джейлбрейки.

- Tethered(привязанные) джейлбрейки не сохраняются при перезагрузках, поэтому для повторного применения джейлбрейка требуется, чтобы устройство было подключено (привязано) к компьютеру во время каждой перезагрузки. Устройство может не перезагружаться вообще, если компьютер не подключен.

- Semi-tethered(полу-привязанные) джейлбрейки не могут быть повторно применены, если устройство не подключено к компьютеру во время перезагрузки. Устройство также может самостоятельно загрузиться в не-jailbroken режим.

- Semi-untethered(полу-отвязанные) джейлбрейки позволяют устройству самостоятельно загружаться, но патчи ядра для отключения шифрования кода не применяются автоматически. Пользователь должен повторно выполнить джейлбрейк устройства, запустив приложение или посетив веб-сайт.

- Untethered(отвязанные) джейлбрейкис- самый популярный выбор для конечных пользователей, потому что его нужно применить только один раз, после чего устройство будет постоянно взломанным.

#### Предостережения и соображения

Джейлбрейк iOS-устройства становится все более и более сложным, потому что Apple продолжает укреплять систему и исправлять уязвимости. Джейлбрейк стал очень чувствительным к времени, потому что Apple перестает подписывать эти уязвимые версии довольно быстро после выпуска исправления (если только уязвимость не является уязвимостью по причине аппаратного обеспечения). Это означает, что вы не сможете установить определенную версию iOS после того, как Apple перестанет подписывать прошивку.

Если у вас есть джейлбрейк устройство, которое вы используете для тестирования безопасности, оставте его как есть, если вы на 100% не уверены, что сможете выполнить джейл после обновления до последней версии iOS. Подумайте о том, чтобы получить запасное устройство (которое будет обновляться с каждой крупной версией iOS) и ждать, когда будет выпущен джейлбрейк публично. Apple, как правило, быстро выпускает патч после того, как был выпущен джейлбрейк публично, поэтому у вас есть только пару дней, чтобы перейти к уязвимой версии iOS и сделать джейлбрейк.

Обновления iOS основаны на процессе запроса-ответа. Устройство разрешит установку ОС только в том случае, если ответ на вызов будет подписан Apple. Это то, что исследователи называют «окном подписи», и именно по этой причине вы не можете просто хранить пакет прошивки OTA, загруженный через iTunes, и загружать его на устройство, когда захотите. Во время незначительных обновлений iOS две версии могут быть подписаны Apple. Это единственная ситуация, когда вы можете понизить версию iOS устройства. Вы можете проверить текущее окно подписи и загрузить прошивку OTA с веб-сайта [IPSW Downloads] (https://ipsw.me "IPSW Downloads").

#### Какой инструмент джейлбрейка использовать

Различные версии iOS требуют разных методов джейлбрейка. [Определите, доступен ли публичный джейлбрейк для вашей версии iOS] (https://canijailbreak.com/ "Can I Jailbreak"). Остерегайтесь поддельных инструментов и программ-шпионов, которые часто скрываются за именами доменов, которые похожи на имя группы/автора джейлбрейка.

Jailbreak Pangu 1.3.0 доступен для 64-разрядных устройств под управлением iOS 9.0. Если у вас есть устройство, на котором установлена ​​версия iOS, для которой нет джейлбрейка, вы по-прежнему можете сделать джейлбрейк на устройстве, если вы откатитесь или обновитесь до версии iOS, _позволяющей сделать джейл(jailbreakable)_ (через загрузку IPSW и iTunes). Однако это может быть невозможно, если требуемая версия iOS больше не подписывается Apple.

Сцена джейлбрейка iOS развивается так быстро, что предоставление свежих инструкций затруднено. Однако мы можем указать вам некоторые источники, которые в настоящее время надежны.

- [Can I Jailbreak?](https://canijailbreak.com/ "Can I Jailbreak?")
- [Вики iPhone] (https://www.theiphonewiki.com/ "Викитека для iPhone")
- [Redmond Pie] (https://www.redmondpie.com/ "Redmond Pie")
- [Reddit Jailbreak] (https://www.reddit.com/r/jailbreak/ "Reddit Jailbreak")

> Обратите внимание, что OWASP и MSTG не будут нести ответственность, если вы в конце концов превратите свое iOS устройство в кирпич!

#### Работа с обнаружением джейлбрейка

Некоторые приложения пытаются определить, является ли устройство iOS, на котором они запущены, взломанным. Это связано с тем, что джейлбрейк деактивирует некоторые механизмы безопасности по умолчанию в iOS. Тем не менее, есть несколько способов обойти это обнаружение, и мы представим их в главах «Обратное проектирование и фальсификация в iOS» и «Тестирование защиты от обратного проектирования в iOS».

#### Конфигурация джейлбрейкнутого устройства

![Cydia Store](Images/Chapters/0x06b/cydia.png)

После того, как вы произвели джейл iOS устройства, и Cydia была установлена (как показано на скриншоте выше), действуйте следующим образом:

1. Из Cydia установите aptitude и openssh.
2. Подключитесь через SSH на ваше устройство iOS.
   - Пользователями по умолчанию являются «root» и «mobile».
   - Пароль по умолчанию - `alpine`.
3. Измените пароль по умолчанию для пользователей `root` и` mobile`.
4. Добавьте в Cydia следующий репозиторий: `https://build.frida.re`.
5. Установите Frida из Cydia.

Cydia позволяет управлять репозиториями. Один из самых популярных репозиториев - BigBoss. Если ваша установка Cydia не была предварительно настроена на использование этого репозитория, вы можете добавить его, перейдя в раздел «Источники» -> «Редактировать», затем нажмите «Добавить» в верхнем-левом углу и введите следующий URL-адрес:

```
http://apt.thebigboss.org/repofiles/cydia/
```

Вы также можете добавить репозиторий HackYouriPhone для получения пакета AppSync:

```
http://repo.hackyouriphone.org
```

Ниже приведены некоторые полезные пакеты, которые вы можете установить из Cydia для начала работы:

- BigBoss Recommended Tools: Устанавливает множество полезных инструментов командной строки для тестирования безопасности, включая стандартные утилиты Unix, отсутствующие в iOS, включая wget, unrar, less и sqlite3 client.
- adv-cmds: расширенная командная строка. Включает в себя finger, fingerd, last, lsvfs, md и ps.
- [Консоль установщика IPA] (https://cydia.saurik.com/package/com.autopear.installipa/ "IPA Installer Console"): инструмент для установки приложений IPA из командной строки. Имя пакета - `com.autopear.installipa`.
- Class Dump: инструмент командной строки для проверки информации о среде исполнения Objective-C, хранящейся в файлах Mach-O.
- Substrate: платформа, которая упрощает разработку сторонних твиков для iOS.
- Сycript: Cycript - это встроенный, оптимизирующий компилятор Cycript-to-JavaScript и консольная среда режима реального времени, которая может быть внедрена в запущенные процессы.
- AppList: позволяет разработчикам запрашивать список установленных приложений и предоставляет панель предпочтений, основываясь на списке.
- PreferenceLoader: утилита, на основе MobileSubstrate, которая позволяет разработчикам добавлять записи в приложение «Настройки», аналогично SettingsBundle, которые используют приложения App Store.
- AppSync Unified: позволяет синхронизировать и устанавливать неподписанные приложения iOS.

На вашей рабочей станции должно быть установлено как минимум следующее:

- клиент SSH
- перехватывающий прокси. В этом руководстве мы будем использовать [BURP Suite] (https://portswigger.net/burp).

Другие полезные инструменты, на которые мы будем ссылаться в руководстве:

- [Introspy](https://github.com/iSECPartners/Introspy-iOS)
- [Frida](https://www.frida.re)
- [IDB](https://www.idbtool.com)
- [Needle](https://github.com/mwrlabs/needle)

### Статический анализ

Предпочтительный метод статического анализа приложений iOS включает использование исходных файлов проекта Xcode. В идеале вы сможете скомпилировать и отладить приложение, чтобы быстро определить любые возможные проблемы с исходным кодом.

Анализ blackbox приложений iOS, без доступа к исходному коду, требует пременение обратного проектирования. Например, никакие декомпиляторы не доступны для приложений iOS, поэтому для глубокой проверки вам необходимо читать ассемблерный код. В этой главе мы не будем вдаваться в подробности ассемблерного кода, но мы перейдем к теме в разделе «Обратное проектирование и вмешательство в iOS».

Инструкции по статическому анализу в следующих главах основаны на предположении, что исходный код доступен.

#### Автоматические инструменты статического анализа

Доступны несколько автоматизированных инструментов для анализа приложения iOS; большинство из них являются коммерческими инструментами. Бесплатные инструменты с открытым исходным кодом [MobSF] (https://github.com/MobSF/Mobile-Security-Framework-MobSF "Система мобильной безопасности (MobSF)") и [Needle] (https://github.com/mwrlabs/needle "Needle") имеют некоторые функции статического и динамического анализа. Дополнительные инструменты перечислены в разделе «Анализ статического исходного кода» в приложении «Инструменты тестирования».

Не уклоняйтесь от использования автоматических сканеров для анализа - они помогают вам собирать низко висящие фрукты и позволяют сосредоточиться на более интересных аспектах анализа, таких как бизнес-логика. Имейте в виду, что статические анализаторы могут создавать ложно-положительные и ложно-отрицательные результаты; всегда внимательно проверяйте результаты.

### Динамический анализ взломанных устройств

Жизнь легка с джейлбрейкнутым устройством: вы не только получаете легкий доступ к песочнице приложения, отсутствие подписи кода позволяет использовать более мощные методы динамического анализа. В iOS большинство инструментов динамического анализа основаны на Cydia Substrate, платформе для разработки патчей времени выполнения, которые мы рассмотрим позже. Для базового мониторинга API вы можете обойтись без знания всех подробностей о том, как работает Substrate - вы можете просто использовать существующие инструменты мониторинга API.

#### Needle

[Needle](https://github.com/mwrlabs/needle "Needle on GitHub") - является универсальной системой проверки безопасности iOS. В следующем разделе приведены шаги, необходимые для установки и использования Needle.

##### Установка Needle

**в Linux**

Следующие команды устанавливают зависимости, необходимые для запуска Needle в Linux.

```shell
# Unix packages
sudo apt-get install python2.7 python2.7-dev sshpass sqlite3 lib32ncurses5-dev

# Python packages
sudo pip install readline paramiko sshtunnel frida mitmproxy biplist

# Download source
git clone https://github.com/mwrlabs/needle.git

```

**в Mac**

Следующие команды устанавливают зависимости, необходимые для запуска Needle в macOS.

```shell
# Core dependencies
brew install python
brew install libxml2
xcode-select --install

# Python packages
sudo -H pip install --upgrade --user readline
sudo -H pip install --upgrade --user paramiko
sudo -H pip install --upgrade --user sshtunnel
sudo -H pip install --upgrade --user frida
sudo -H pip install --upgrade --user biplist
# sshpass
brew install https://raw.githubusercontent.com/kadwanev/bigboybrew/master/Library/Formula/sshpass.rb

# mitmproxy
wget https://github.com/mitmproxy/mitmproxy/releases/download/v0.17.1/mitmproxy-0.17.1-osx.tar.gz
tar -xvzf mitmproxy-0.17.1-osx.tar.gz
sudo cp mitmproxy-0.17.1-osx/mitm* /usr/local/bin/

# Download source
git clone https://github.com/mwrlabs/needle.git
```

##### Установка Needle Agent

Единственным предварительным условием является джейлбрейк устройство со следующими пакетами:

- `Cydia`
- `Apt 0.7 Strict`

(Для несущественных предварительных условий смотри [зависимости устройства](https://github.com/mwrlabs/needle/wiki/Quick-Start-Guide#device-dependencies)).

- Добавьте следующий источник в источники Cydia: http://mobiletools.mwrinfosecurity.com/cydia/
- Найдите пакет NeedleAgent и установите его.

![](https://raw.githubusercontent.com/mwrlabs/needle/master/.github/install_agent_1.jpg)  ![](https://raw.githubusercontent.com/mwrlabs/needle/master/.github/install_agent_2.jpg)

* Если процесс установки завершится успешно, вы найдете приложение NeedleAgent на главном экране.

![](https://raw.githubusercontent.com/mwrlabs/needle/master/.github/install_agent_3.jpg)

##### Запуск библиотеки

**Запуск NeedleAgent**

- Откройте приложение NeedleAgent на вашем устройстве.
- Нажмите на кнопку "Listen" в левом верхнем углу, и NeedleAgent начнет слушать порт `4444` по умолчанию. Порт по умолчанию можно изменить через поле ввода в верхнем-правом углу.

![](https://raw.githubusercontent.com/mwrlabs/needle/master/.github/install_agent_4.jpg)

**Запуск Needle**

Чтобы запустить Needle, откройте консоль и напишите:

```shell
$ python needle.py
      __  _ _______ _______ ______         ______
      | \ | |______ |______ | \     |      |______
      | \_| |______ |______ |_____/ |_____ |______
                  Needle v1.0 [mwr.to/needle]
    [MWR InfoSecurity (@MWRLabs) - Marco Lancini (@LanciniMarco)]

[needle] > help
Commands (type [help|?] <topic>):
---------------------------------
back exit info kill pull reload search shell show use
exec_command help jobs load push resource set shell_local unset

[needle] > show options

  Name                      Current Value                Required  Description
  ------------------------  -------------                --------  -----------
  AGENT_PORT                4444                         yes       Port on which the Needle Agent is listening
  APP                                                    no        Bundle ID of the target application (e.g., com.example.app). Leave empty to launch wizard
  DEBUG                     False                        yes       Enable debugging output
  HIDE_SYSTEM_APPS          False                        yes       If set to True, only 3rd party apps will be shown
  IP                        127.0.0.1                    yes       IP address of the testing device (set to localhost to use USB)
  OUTPUT_FOLDER             /root/.needle/output         yes       Full path of the output folder, where to store the output of the modules
  PASSWORD                  ********                     yes       SSH Password of the testing device
  PORT                      2222                         yes       Port of the SSH agent on the testing device (needs to be != 22 to use USB)
  PUB_KEY_AUTH              True                         yes       Use public key auth to authenticate to the device. Key must be present in the ssh-agent if a passphrase is used
  SAVE_HISTORY              True                         yes       Persists command history across sessions
  SKIP_OUTPUT_FOLDER_CHECK  False                        no        Skip the check that ensures the output folder does not already contain other files. It will automatically overwrite any file
  USERNAME                  root                         yes       SSH Username of the testing device
  VERBOSE                   True                         yes       Enable verbose output

[needle] >
```

Вам будет представлен интерфейс командной строки Needle.

Инструмент имеет следующие глобальные параметры (перечислить их можно с помощью команды `show options` и установить их - `set <option> <value>`):

- **USERNAME, PASSWORD**: учетных данных SSH тестируемого устройства (значения по умолчанию: «root» и «alpine», соответственно)
- **PUB_KEY_AUTH**: используйте аутентификацию с использованием открытого ключа для службы SSH, запущенной на устройстве. Ключ должен быть в ssh-agent, если используется кодовая фраза.
- **IP, PORT**: менеджер сеансов, встроенный в ядро Needle, может обрабатывать соединения Wi-Fi или USB SSH. Если выбран SSH-over-USB, параметр IP должен быть установлен на localhost («set IP 127.0.0.1»), а PORT должен быть установлен на что угодно, кроме 22 («set PORT 2222»).
- **AGENT_PORT**: порт, который слушает установленный NeedleAgent.
- **APP**: это идентификатор пакета приложения, который будет проанализирован (например, «com.example.app»). Если вы не знаете этого заранее, вы можете оставить поле пустым. Затем Needle запустит мастера, предлагающего пользователю выбрать приложение.
- **OUTPUT_FOLDER**: это полный путь к папке с результатами, где Needle будет хранить весь вывод модуля.
- **SKIP_OUTPUT_FOLDER_CHECK**: если установлено значение «true», папка вывода не будет проверяться на наличие ранее существующих файлов.
- **HIDE_SYSTEM_APPS**: если установлено значение «true», будут показаны только сторонние приложения.
- **SAVE_HISTORY**: если установлено значение «true», история команд будет сохраняться через сессии.
- **VERBOSE, DEBUG**: если установлено значение «true», это включает подробный и отладочный лог, соответственно.

#### Подключение к SSH через USB

Во время реального тестирования blackbox надежное соединение Wi-Fi может быть недоступно. В этой ситуации вы можете использовать [usbmuxd] (https://github.com/libimobiledevice/usbmuxd "usbmuxd") для подключения к SSH-серверу вашего устройства через USB.

Usbmuxd - демон, который мониторит подключения iPhone через сокеты. Вы можете использовать его для сопоставления сокетов локального хоста мобильного устройства с портами TCP на хост-машине. Это позволяет удобно использовать SSH на вашем устройстве iOS без настройки фактического сетевого подключения. Когда usbmuxd обнаруживает, что iPhone работает в обычном режиме, он подключается к телефону и начинает ретранслировать запросы, которые он получает через `/var/run/usbmuxd`.

Подключите устройство iOS к macOS, установив и запустив iproxy:

```shell
$ brew install libimobiledevice
$ iproxy 2222 22
waiting for connection
```

Вышеупомянутая команда отображает порт `22` на устройстве iOS на порт `2222` на localhost. С помощью следующей команды вы можете подключиться к устройству:

```shell
$ ssh -p 2222 root@localhost
root@localhost's password:
iPhone:~ root#
```

Вы также можете подключиться к USB вашего iPhone через [Needle](https://labs.mwrinfosecurity.com/blog/needle-how-to/ "Needle").

#### Структура папки с приложением

Системные приложения находятся в каталоге `/Applications`. Вы можете использовать [IPA Installer Console](https://cydia.saurik.com/package/com.autopear.installipa "IPA Installer Console") , чтобы определить папку установки для установленных пользователем приложений (доступно в разделе `/private/var/mobile/Containers/` с iOS 9). Подключитесь к устройству через SSH и запустите команду `ipainstaller` (делает то же самое, что и `installipa`) следующим образом:

```shell
iPhone:~ root# ipainstaller -l
...
sg.vp.UnCrackable1

iPhone:~ root# ipainstaller -i sg.vp.UnCrackable1
...
Bundle: /private/var/mobile/Containers/Bundle/Application/A8BD91A9-3C81-4674-A790-AF8CDCA8A2F1
Application: /private/var/mobile/Containers/Bundle/Application/A8BD91A9-3C81-4674-A790-AF8CDCA8A2F1/UnCrackable Level 1.app
Data: /private/var/mobile/Containers/Data/Application/A8AE15EE-DC8B-4F1C-91A5-1FED35258D87
```
Установленные пользователем приложения имеют два основных подкаталога (плюс подкаталог `Shared` с iOS 9):

- Bundle
- Data

Подкаталог приложения, находящийся внутри подкаталога Bundle, содержит имя приложения. Статические файлы установщика находятся в каталоге приложения, и все пользовательские данные находятся в каталоге данных.

Случайная строка в URI - это GUID приложения. Каждая установка приложения имеет уникальный GUID. Нет никакой связи между Bundle GUID и Data GUID.

#### Копирование файлов приложения

Файлы приложения хранятся в каталоге Data. Чтобы определить правильный путь, подключитесь через SSH к устройству и используйте IPA Installer Console для извлечения информации о пакете (как показано далее):

```shell
iPhone:~ root# ipainstaller -l
...
sg.vp.UnCrackable1

iPhone:~ root# ipainstaller -i sg.vp.UnCrackable1
Identifier: sg.vp.UnCrackable1
Version: 1
Short Version: 1.0
Name: UnCrackable1
Display Name: UnCrackable Level 1
Bundle: /private/var/mobile/Containers/Bundle/Application/A8BD91A9-3C81-4674-A790-AF8CDCA8A2F1
Application: /private/var/mobile/Containers/Bundle/Application/A8BD91A9-3C81-4674-A790-AF8CDCA8A2F1/UnCrackable Level 1.app
Data: /private/var/mobile/Containers/Data/Application/A8AE15EE-DC8B-4F1C-91A5-1FED35258D87
```

Теперь вы можете просто архивировать каталог данных и вытащить его с устройства с помощью `scp`:

```shell
iPhone:~ root# tar czvf /tmp/data.tgz /private/var/mobile/Containers/Data/Application/A8AE15EE-DC8B-4F1C-91A5-1FED35258D87
iPhone:~ root# exit
$ scp -P 2222 root@localhost:/tmp/data.tgz .
```

#### Полученние данных Keychain

[Keychain-Dumper](https://github.com/ptoomey3/Keychain-Dumper/) позволяет вам копировать содержимое Keychain с джейлбрейкнутого устройства. Самый простой способ получить этот инструмент - загрузить его из репозитория GitHub:

```shell
$ git clone https://github.com/ptoomey3/Keychain-Dumper
$ scp -P 2222 Keychain-Dumper/keychain_dumper root@localhost:/tmp/
$ ssh -p 2222 root@localhost
iPhone:~ root# chmod +x /tmp/keychain_dumper
iPhone:~ root# /tmp/keychain_dumper

(...)

Generic Password
----------------
Service: myApp
Account: key3
Entitlement Group: RUD9L355Y.sg.vantagepoint.example
Label: (null)
Generic Field: (null)
Keychain Data: SmJSWxEs

Generic Password
----------------
Service: myApp
Account: key7
Entitlement Group: RUD9L355Y.sg.vantagepoint.example
Label: (null)
Generic Field: (null)
Keychain Data: WOg1DfuH
```

Обратите внимание, что этот бинарный файл подписан с самозаверяющим сертификатом, который имеет привелегию «wildcard». Это право предоставляет доступ ко *всем* элементам в Keychain. Если вы являетесь параноиком или имеете очень чувствительные личные данные на вашем тестовом устройстве, вы можете захотеть скомпилировать инструмент из исходников и вручную вставить соответствующие права на вашу сборку; инструкции для этого доступны в репозитории GitHub.

#### Установка Frida

[Frida](https://www.frida.re "Frida") представляет собой набор средств инструментирования, которая позволяет вам добавлять фрагменты JavaScript или части вашей собственной библиотеки в нативные приложения для Android и iOS. Если вы уже прочитали раздел Android этого руководства, вы должны быть хорошо знакомы с этим инструментом.

Если вы еще этого не сделали, вам необходимо установить пакет Python Frida на вашу хост-машину:

```shell
$ pip install frida
```

Чтобы подключить Frida к iOS-приложению, вам нужен способ инъекции среды Frida в это приложение. Это легко сделать на джейлбрейк-устройстве: просто установите `frida-server` через Cydia. Как только он будет установлен, сервер Frida будет автоматически запускаться с правами root, что позволит вам легко вставлять код в любой процесс.

Запустите Cydia и добавьте репозиторий Frida, нажав Управление -> Источники -> Изменить -> Добавить и ввести https://build.frida.re. Затем вы сможете найти и установить пакет Frida.

Подключите устройство через USB и убедитесь, что Frida работает, выполнив команду `frida-ps` и флаг '-U'. Это должно вернуть список процессов, запущенных на устройстве:


```shell
$ frida-ps -U
PID  Name
---  ----------------
963  Mail
952  Safari
416  BTServer
422  BlueTool
791  CalendarWidget
451  CloudKeychainPro
239  CommCenter
764  ContactsCoreSpot
(...)
```
<!--- Данный раздел был выпилен из мастера MSTG на момент 11.07.2018
Ниже мы продемонстрируем еще несколько вариантов использования Frida, но давайте сначала посмотрим, что вы должны сделать, если вам придется работать на не-джейлбрейк-устройстве.

### Динамический анализ на неджейлбрейкнутом устройстве

Если у вас нет доступа к джейлбрейк-устройству, вы можете пропатчить и переупаковать целевое приложение для загрузки динамической библиотеки при запуске. Таким образом, вы можете настроить приложение и сделать практически все, что вам нужно для динамического анализа (конечно, вы не можете вырваться из песочницы таким образом, но вам это будет необязательно). Однако этот метод работает только в том случае, если бинарное приложение не является зашифрованным через FairPlay (т.е. полученным из магазина приложений).

Благодаря запутанной системе подписи кода и профилирования Apple, переподписывание приложения является более сложным, чем вы  могли ожидать. iOS не запускает приложение, если вы точно не получите provisioning profile и code signature header. Это требует изучения многих концепций - типов сертификатов, идентификаторов пакетов, идентификаторов приложений, идентификаторов команд и способов их подключения к инструментам сборки Apple. Достаточно сказать, что заставить ОС запускать двоичный файл, который не был построен по умолчанию (через Xcode), может быть сложным процессом.

Мы будем использовать `optool`, инструменты сборки Apple и некоторые команды оболочки. Наш способ был вдохновлен [Vincent Tan's Swizzler project](https://github.com/vtky/Swizzler2/ "Swizzler"). [The NCC group](https://www.nccgroup.trust/au/about-us/newsroom-and-events/blogs/2016/october/ios-instrumentation-without-jailbreak/ "NCC blog - iOS instrumentation without jailbreak"), где описан алтернативный метод переупаковки.

Чтобы повторить перечисленные ниже шаги, загрузите [UnCrackable iOS App Level 1](https://github.com/OWASP/owasp-mstg/tree/master/Crackmes/iOS/Level_01 "Crackmes - iOS Level 1") из репозитория OWASP Mobile Testing Guide. Наша цель - произвести инъекцию `FridaGadget.dylib` в приложение UnCrackable во время запуска, чтобы мы могли инструментировать его с помощью Frida.

> Обратите внимание, что следующие шаги применимы только к macOS, поскольку Xcode доступен только для macOS.

#### Получение Provisioning Profile и сертификата разработчика

*Provisioning profile* является файлом plist, подписанным Apple. Он одобряет ваш сертификат подписи кода на одном или нескольких устройствах. Другими словами, это означает, что Apple явно разрешает вашему приложению запускаться по определенным причинам, например отладка на выбранных устройствах (в профиле разработки). Provisioning profile также включает *entitlements*, предоставленные вашему приложению. *Сертификат* содержит закрытый ключ, который вы будете использовать для подписи.

В зависимости от того, зарегистрирован ли вы как разработчик iOS, вы можете получить provisioning profile и сертификат одним из следующих способов:

**С наличием официального аккаунта "iOS Developer" от Apple:**

Если вы уже разрабатывали и распространяли приложения iOS с Xcode, у вас уже есть собственный сертификат подписи кода. Используйте инструмент *security*, чтобы показать свои идентификаторы подписи:

```shell
$ security find-identity -v
  1) 61FA3547E0AF42A11E233F6A2B255E6B6AF262CE "iPhone Distribution: Vantage Point Security Pte. Ltd."
  2) 8004380F331DCA22CC1B47FB1A805890AE41C938 "iPhone Developer: Bernhard Müller (RV852WND79)"
```

Войдите в портал разработчика Apple, чтобы выпустить новый App ID, а затем выпустить и загрузить provisioning profile. Идентификатор приложения - это строка из двух частей, состоящая из Team ID, предоставленного Apple, и строки поиска Bundle ID, которую вы можете установить на произвольное значение, например `com.example.myapp`. Обратите внимание, что вы можете использовать один App ID для переподписи нескольких приложений. Убедитесь, что вы создали provisioning profile *development*, а не профиль *distribution*, чтобы вы могли отлаживать приложение.

В приведенных ниже примерах мы используем нашу собственную подпись, которая связана с командой разработчиков нашей компании. Для этих примеров я создал app-id «sg.vp.repackaged» и профиль подготовки «AwesomeRepackaging». Я закончил процесс, получив файл `AwesomeRepackaging.mobileprovision`, - замените это своим собственным именем файла в командах оболочки ниже.

**С обычным аккаунтом iTunes:**

Apple предоставит вам бесплатный профиль разработки, даже если вы не являетесь платящим разработчиком. Вы можете получить профиль с помощью Xcode и обычной учетной записи Apple: просто создайте пустой проект iOS и извлеките `embedded.mobileprovision` из контейнера приложений, который находится в подкаталоге Xcode вашего домашнего каталога:`~/Library/Developer/Xcode/DerivedData/<ProjectName>/Build/Products/Debug-iphoneos/<ProjectName>.app/`. [NCC blog post "iOS instrumentation without jailbreak"] (https://www.nccgroup.trust/au/about-us/newsroom-and-events/blogs/2016/october/ios-instrumentation-without-jailbreak/ "iOS instrumentation without jailbreak") подробно объясняет этот процесс.

Получив provisioning profile, вы можете проверить его содержимое командой `security`. Помимо разрешенных сертификатов и устройств вы найдете права(entitlements), предоставляемые приложению в профиле. Вам они понадобятся для подписи кода, поэтому извлеките их в отдельный файл plist, как показано ниже. Посмотрите содержимое файла, чтобы убедиться, что все прошло как ожидалось.


```shell
$ security cms -D -i AwesomeRepackaging.mobileprovision > profile.plist
$ /usr/libexec/PlistBuddy -x -c 'Print :Entitlements' profile.plist > entitlements.plist
$ cat entitlements.plist
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>application-identifier</key>
	<string>LRUD9L355Y.sg.vantagepoint.repackage</string>
	<key>com.apple.developer.team-identifier</key>
	<string>LRUD9L355Y</string>
	<key>get-task-allow</key>
	<true/>
	<key>keychain-access-groups</key>
	<array>
		<string>LRUD9L355Y.*</string>
	</array>
</dict>
</plist>
```

Обратите внимание на идентификатор приложения, который представляет собой комбинацию идентификатора команды (LRUD9L355Y) и идентификатора пакета (sg.vantagepoint.repackage). Этот provisioning profile действителен только для приложения, имеющего этот идентификатор приложения. Также важна клавиша «get-task-allow» - если установлено значение «true», другим приложениям (таким как сервер отладки) разрешено присоединяться к приложению (следовательно, этот ключ будет установлен на «false» в distribution profile).

#### Другие подготовительные действия

Чтобы наше приложение загрузило дополнительную библиотеку при запуске, нам нужно каким-то образом вставить дополнительную команду загрузки в заголовок Mach-O основного исполняемого файла. [Optool] (https://github.com/alexzielenski/optool "Optool") может автоматизировать этот процесс:

```shell
$ git clone https://github.com/alexzielenski/optool.git
$ cd optool/
$ git submodule update --init --recursive
$ xcodebuild
$ ln -s <your-path-to-optool>/build/Release/optool /usr/local/bin/optool
```

Мы также будем использовать [ios-deploy] (https://github.com/phonegap/ios-deploy "ios-deploy"), инструмент, позволяющий отлаживать и развертывать приложения iOS без Xcode:

```shell
$ git clone https://github.com/phonegap/ios-deploy.git
$ cd ios-deploy/
$ xcodebuild
$ cd build/Release
$ ./ios-deploy
$ ln -s <your-path-to-ios-deploy>/build/Release/ios-deploy /usr/local/bin/ios-deploy
```

Последние строки в примерах optool и ios-deploy создают символическую ссылку и делают исполняемый файл доступным для всей системы.

Перезагрузите свою оболочку, чтобы новые команды были доступны:

```shell
zsh: # . ~/.zshrc
bash: # . ~/.bashrc
```

Чтобы повторить примеры ниже вам также понадобится `FridaGadget.dylib`:

```shell
$ curl -O https://build.frida.re/frida/ios/lib/FridaGadget.dylib
```

Помимо перечисленных выше инструментов, мы будем использовать стандартные инструменты, которые поставляются с macOS и Xcode. Убедитесь, что у вас есть [Xcode command line developer tools](https://railsapps.github.io/xcode-command-line-tools.html "Xcode Command Line Tools").

#### Патч, переупакова, переподпись

Время становиться серьезными! Как вы уже знаете, файлы IPA на самом деле являются ZIP-архивами, поэтому вы можете использовать любой инструмент zip для распаковки архива. Скопируйте `FridaGadget.dylib` в каталог приложения и используйте optool, чтобы добавить команду load в двоичный файл` UnCrackable Level 1`.

```shell
$ unzip UnCrackable_Level1.ipa
$ cp FridaGadget.dylib Payload/UnCrackable\ Level\ 1.app/
$ optool install -c load -p "@executable_path/FridaGadget.dylib"  -t Payload/UnCrackable\ Level\ 1.app/UnCrackable\ Level\ 1
Found FAT Header
Found thin header...
Found thin header...
Inserting a LC_LOAD_DYLIB command for architecture: arm
Successfully inserted a LC_LOAD_DYLIB command for arm
Inserting a LC_LOAD_DYLIB command for architecture: arm64
Successfully inserted a LC_LOAD_DYLIB command for arm64
Writing executable to Payload/UnCrackable Level 1.app/UnCrackable Level 1...
```

Разумеется, такая вопиющая подделка делает недействительной сигнатуру кода основного исполняемого файла, поэтому это не будет выполняться на устройстве без джейлбрейка. Вам нужно будет заменить provisioning profile и подписать как основной исполняемый файл, так и `FridaGadget.dylib` с сертификатом, указанным в профиле.

Во-первых, давайте добавим в пакет собственный provisioning profile:

```shell
$ cp AwesomeRepackaging.mobileprovision Payload/UnCrackable\ Level\ 1.app/embedded.mobileprovision
```

Затем нам нужно убедиться, что Bundle ID в «Info.plist» соответствует указанному в профиле, потому что инструмент «codesign» будет считывать Bundle ID из «Info.plist» во время подписи; неправильное значение приведет к недопустимой сигнатуре.

```shell
$ /usr/libexec/PlistBuddy -c "Set :CFBundleIdentifier sg.vantagepoint.repackage" Payload/UnCrackable\ Level\ 1.app/Info.plist
```

Наконец, мы используем `codesign` для повторной подписи двух двоичных файлов. Вместо «8004380F331DCA22CC1B47FB1A805890AE41C938» вам нужно использовать свой идентификатор подписи, который вы можете вывести, выполнив команду `security find-identity -p codesigning -v`.

```shell
$ rm -rf Payload/UnCrackable\ Level\ 1.app/_CodeSignature
$ /usr/bin/codesign --force --sign 8004380F331DCA22CC1B47FB1A805890AE41C938  Payload/UnCrackable\ Level\ 1.app/FridaGadget.dylib
Payload/UnCrackable Level 1.app/FridaGadget.dylib: replacing existing signature
```

`entitlements.plist` файл, созданный нами ранее, для пустого iOS проекта.

```shell
$ /usr/bin/codesign --force --sign 8004380F331DCA22CC1B47FB1A805890AE41C938 --entitlements entitlements.plist Payload/UnCrackable\ Level\ 1.app/UnCrackable\ Level\ 1
Payload/UnCrackable Level 1.app/UnCrackable Level 1: replacing existing signature
```

#### Установка и запуск приложения

Теперь вы должны быть готовы запустить модифицированное приложение. Разверните и запустите приложение на устройстве следующим образом:

```shell
$ ios-deploy --debug --bundle Payload/UnCrackable\ Level\ 1.app/
```

Если все пойдет хорошо, приложение должно запускаться в режиме отладки при подключенном lldb. Теперь Frida может подключаться к приложению. Вы можете проверить это с помощью команды `frida-ps`:

```shell
$ frida-ps -U
PID  Name
---  ------
499  Gadget
```

![Frida on non-JB device](Images/Chapters/0x06b/fridaStockiOS.png "Frida on non-JB device")

#### Исправление проблем

Когда что-то пойдет не так (и это обычно происходит), наиболее вероятными причинами являются несоответствия между provisioning profile и code signing header. Чтение [official documentation](https://developer.apple.com/library/content/documentation/IDEs/Conceptual/AppDistributionGuide/MaintainingProfiles/MaintainingProfiles.html "Maintaining Provisioning Profiles") поможет понять процесс подписи кода. Ресурс Apple [entitlement troubleshooting page](https://developer.apple.com/library/content/technotes/tn2415/_index.html "Entitlements Troubleshooting ") также очень полезен.

#### Автоматическое переподписывание с использованием Objection

[Objection](https://github.com/sensepost/objection "Objection") -это набор инструментов исследования мобильной среды исполнения, основанный на [Frida](https://www.frida.re). Одно из лучших свойств Objection заключается в том, что он работает даже с устройствами, не имеющими джейлбрейка. Он делает это, автоматизируя процесс переупаковки приложений с помощью `FridaGadget.dylib`.
Мы не будем подробно останавливаться на Objection в этом руководстве, но вы можете найти исчерпывающую документацию на [wiki pages](https://github.com/sensepost/objection/wiki "Objection - Documentation") и [how to repackage an IPA](https://github.com/sensepost/objection/wiki/Patching-iOS-Applications "Patching iOS Apps").
--->
Ниже будут продемонстрированы другие варианты использования Frida.

### Трассировка методов с использованием Frida

Перехват методов Objective-C - полезный подход тестирования безопасности iOS. Например, вас могут заинтересовать операции хранения данных или сетевые запросы. В следующем примере мы напишем простой трассировщик для протоколирования запросов HTTP(S), созданных с помощью стандартных HTTP API iOS. Мы также покажем вам, как произвести инъекцию трассировщика в веб-браузер Safari.

В следующих примерах мы предположим, что вы работаете на джейлбрейк-устройстве.
<!--- Если это не так, сначала необходимо выполнить шаги, описанные в предыдущем разделе, чтобы переупаковать приложение Safari. --->

Frida поставляется с `frida-trace` - готовым инструментом отслеживания функций. `frida-trace` принимает методы Objective-C с помощью флага `-m`. Вы можете передать ему wildcard `- [NSURL *]`, например, `frida-trace` будет автоматически устанавливать перехваты во всех селекторах классов` NSURL`. Мы будем использовать это, чтобы получить общее представление о том, какие библиотечные функции вызывает Safari, когда пользователь открывает URL-адрес.

Запустите Safari на устройстве и убедитесь, что устройство подключено через USB. Затем запустите `frida-trace` следующим образом:

```shell
$ frida-trace -U -m "-[NSURL *]" Safari
Instrumenting functions...                                              
-[NSURL isMusicStoreURL]: Loaded handler at "/Users/berndt/Desktop/__handlers__/__NSURL_isMusicStoreURL_.js"
-[NSURL isAppStoreURL]: Loaded handler at "/Users/berndt/Desktop/__handlers__/__NSURL_isAppStoreURL_.js"
(...)
Started tracing 248 functions. Press Ctrl+C to stop.
```

Затем перейдите на новый веб-сайт в Safari. Вы должны увидеть отслеживаемые вызовы функций в консоли `frida-trace`. Обратите внимание, что метод `initWithURL:` вызывается для инициализации нового объекта запроса URL.

```shell
           /* TID 0xc07 */
  20313 ms  -[NSURLRequest _initWithCFURLRequest:0x1043bca30 ]
 20313 ms  -[NSURLRequest URL]
(...)
 21324 ms  -[NSURLRequest initWithURL:0x106388b00 ]
 21324 ms     | -[NSURLRequest initWithURL:0x106388b00 cachePolicy:0x0 timeoutInterval:0x106388b80
```

Мы можем посмотреть объявление этого метода на [сайте Apple Developer](https://developer.apple.com/documentation/foundation/nsbundle/1409352-initwithurl?language=objc "Apple Developer Website - initWithURL Instance Method"):

```objc
- (instancetype)initWithURL:(NSURL *)url;
```

Метод вызывается с единственным аргументом - объектом `NSURL`. Согласно [документации](https://developer.apple.com/documentation/foundation/nsurl?language=objc "Apple Developer Website - NSURL class"), класс `NSRURL` имеет свойство `absoluteString`, значение которого должно быть абсолютным URL-адресом, представленным объектом `NSURL`.

Теперь у нас есть вся информация, необходимая для написания скрипта Frida, который перехватывает метод `initWithURL:` и печатает URL-адрес, переданный методу. Ниже приведен полный исходный код. Убедитесь, что вы прочитали код и комментарии, чтобы понять что происходит.

```python
import sys
import frida


// JavaScript to be injected
frida_code = """

	// Obtain a reference to the initWithURL: method of the NSURLRequest class
    var URL = ObjC.classes.NSURLRequest["- initWithURL:];

    // Intercept the method
    Interceptor.attach(URL.implementation, {
      onEnter: function(args) {

      	// We should always initialize an autorelease pool before interacting with Objective-C APIs

        var pool = ObjC.classes.NSAutoreleasePool.alloc().init();

        var NSString = ObjC.classes.NSString;

        // Obtain a reference to the NSLog function, and use it to print the URL value
        // args[2] refers to the first method argument (NSURL *url)

        var NSLog = new NativeFunction(Module.findExportByName('Foundation', 'NSLog'), 'void', ['pointer', '...']);

        NSLog(args[2].absoluteString_());

        pool.release();
      }
    });


"""

process = frida.get_usb_device().attach("Safari")
script = process.create_script(frida_code)
script.on('message', message_callback)
script.load()

sys.stdin.read()
```

Запустите Safari на устройстве iOS. Запустите вышеуказанный скрипт Python на подключенном хосте и откройте лог устройства(мы объясним, как открыть лог устройства в следующем разделе). Попробуйте открыть новый URL-адрес в Safari; вы должны увидеть вывод Frida в логах.

![Лог Frida в Xcode](Images/Chapters/0x06c/frida-xcode-log.png)

Конечно, этот пример иллюстрирует только одну из вещей, которые вы можете сделать с Frida. Чтобы осмыслить весь потенциал инструмента, вы должны научиться использовать его [JavaScript API](https://www.frida.re/docs/javascript-api/ "Frida JavaScript API reference"). На сайте Frida, в разделе документации есть [руководство](https://www.frida.re/docs/ios/ "Frida Tutorial") и [примеры](https://www.frida.re/docs/examples/ios/ "Frida examples") использования Frida в iOS.

### Мониторинг логов консоли

Многие приложения регистрируют информационные(и потенциально чувствительные) сообщения в лог консоли. Лог также содержит отчеты о сбоях и другую полезную информацию. Вы можете собирать логи консоли через окно «Устройства» Xcode следующим образом:

1. Запустите Xcode.
2. Подключите устройство к компьютеру.
3. В меню окна выберите «Devices».
4. Нажмите на подключенное устройство iOS в левой части окна «Devices».
5. Воспроизведите проблему.
6. Нажмите переключатель "треугольник в коробке", расположенный в нижнем-левом углу правой части окна «Devices», чтобы просмотреть содержимое логов консоли.

Чтобы сохранить вывод консоли в текстовый файл, нажмите на иконку закругленной стрелки, смотрящей вниз, в нижнем-правом углу.

![Мониторинг логов консоли через Xcode](Images/Chapters/0x06b/device_console.jpg)

### Установка веб-прокси Burp Suite

Burp Suite - это интегрированная платформа для тестирования безопасности мобильных и веб-приложений. Его инструменты работают вместе, чтобы поддерживать весь процесс тестирования, от первоначального сопоставления и анализа поверхностей атак до обнаружения и использования уязвимостей безопасности. Burp Proxy работает как веб-прокси-сервер для Burp Suite, который позиционируется как посредник между браузером и веб-серверами. Burp Suite позволяет перехватывать, проверять и изменять входящий и исходящий необработанный HTTP-трафик.

Настройка Burp для проксирования вашего трафика довольно проста. Мы предполагаем, что у вас есть устройство iOS и рабочая станция, подключенная к сети Wi-Fi, которая разрешает передачу трафика клиент-клиент. Если передача трафика клиент-клиент не разрешена, вы можете использовать usbmuxd для подключения к Burp через USB.

Portswigger предоставляет хорошее [руководство по настройке устройства iOS для работы с Burp](https://support.portswigger.net/customer/portal/articles/1841108-configuring-an-ios-device-to-work-with-burp "Configuring an iOS Device to Work With Burp") и [руководство по устрановки сертификата ЦС Burp на устройство iOS](https://support.portswigger.net/customer/portal/articles/1841109-installing-burp-s-ca-certificate-in-an-ios-device "Installing Burp's CA Certificate in an iOS Device").

#### Отключение сertificate pinning

[SSL Kill Switch 2](https://github.com/nabla-c0d3/ssl-kill-switch2 "SSL Kill Switch 2") является одним из способов отключить сertificate pinning. Он может быть установлен через магазин Cydia. Он будет подключаться ко всем вызовам API высокого уровня и обходить сertificate pinning.

Приложение Burp Suite "[Mobile Assistant](https://portswigger.net/burp/help/mobile_testing_using_mobile_assistant.html "Using Burp Suite Mobile Assistant")" также может быть использовано для обхода сertificate pinning.

В некоторых случаях сertificate pinning сложно обходить. Когда вы можете получить доступ к исходному коду и перекомпилировать приложение, найдите следующее:

- API вызывает `NSURLSession`,` CFStream` и `AFNetworking`
- методы/строки, содержащие слова типа «pinning», «X509», «сertificate» и т. д.

Если у вас нет доступа к исходному коду, вы можете попробовать пропатчить бинарник или же выполнить манипуляции со средой исполнения:

- Если используется сertificate pinning OpenSSL, вы можете попробовать [пропатчить бинарник](https://www.nccgroup.trust/us/about-us/newsroom-and-events/blog/2015/january/bypassing-openssl-certificate-pinning-in-ios-apps/ "Bypassing OpenSSL Certificate Pinning in iOS Apps").

- Приложения, написанные с помощью Apache Cordova или Adobe PhoneGap, используют много обратных вызовов. Найдите функцию обратного вызова, которая вызывается в ответ на успешное исполнение, и вручную вызовите ее с помощью Cycript.
- Иногда сертификат представляет собой файл в пакете приложений. Замены сертификата сертификатом Burp может хватить, но будьте осторожны с суммой SHA сертификата. Если он захардкоден в двоичный файл, вы тоже должны его заменить!

Certificate pinning является хорошей практикой безопасности и должен использоваться для всех приложений, которые обрабатывают конфиденциальную информацию. [EFF's Observatory](https://www.eff.org/pl/observatory) перечисляет корневые и промежуточные ЦС(CA), которым доверяют основные операционные системы. Пожалуйста, обратитесь к [карте примерно 650 организаций, являющимимся ЦС и которым прямо или косвенно доверяет Mozilla или Microsoft](https://www.eff.org/files/colour_map_of_CAs.pdf "Map of the 650-odd organizations that function as Certificate Authorities trusted (directly or indirectly) by Mozilla or Microsoft"). Используйте certificate pinning, если вы не доверяете хотя бы одному ЦС из этого списка.

Если вы хотите получить более подробную информацию о тестировании whitebox и типичных шаблонах кода, см. «iOS Application Security» Дэвида Тиля. Там содержатся описания и фрагменты кода, иллюстрирующие наиболее распространенные методы certificate pinning.

Чтобы получить дополнительную информацию о тестировании безопасности уровня передачи данных, обратитесь к разделу «Тестирование сетевых взаимодействий».

### Мониторинг сети/сниффинг

Вы можете удаленно заснифить трафик с iOS устройства с помощью [создания удаленного виртуального интерфейса](https://stackoverflow.com/questions/9555403/capturing-mobile-phone-traffic-on-wireshark/33175819#33175819 "Wireshark + OSX + iOS") для вашего iOS устройства. Сначала убедитесь, что на вашей машине macOS установлен Wireshark.

1. Подключите устройство iOS к компьютеру macOS через USB.
2. Убедитесь, что ваше устройство iOS и компьютер macOS подключены к одной сети.
3. Откройте терминал macOS и введите следующую команду: `$ rvictl -s x`, где x - это UDID вашего устройства iOS. Вы можете найти [UDID вашего устройства iOS через iTunes](http://www.iclarified.com/52179/how-to-find-your-iphones-udid "How to Find Your iPhone's UDID").
4. Запустите Wireshark и выберите «rvi0» в качестве интерфейса захвата.
5. Отфильтруйте трафик в Wireshark, чтобы отобразить, что вы хотите контролировать (например, весь HTTP-трафик, отправленный/полученный по IP-адресу 192.168.1.1).

```shell
ip.addr == 192.168.1.1 && http
```
