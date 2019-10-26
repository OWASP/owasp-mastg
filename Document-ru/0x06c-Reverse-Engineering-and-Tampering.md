## Обратное проектирование и вмешательство в iOS

### Swift и Objective-C

Поскольку Objective-C и Swift принципиально отличаются друг от друга, язык программирования, на котором написано приложение, влияет на возможности его обратного проектирования. Например, Objective-C позволяет изменять вызовы методов во время выполнения. Это упрощает замену других функций в приложении, также этот метод в значительной степени используется в [Cycript] (http://www.cycript.org/ "Cycript") и других инструментами обратного проектирования. Method swizzling реализован по-другому в Swift, что делает его эксплуатацию сложнее чем в Objective-C.

Большая часть этой главы относится к приложениям, написанным на Objective-C или имеющим bridged types, которые являются типами, совместимыми как с Swift, так и с Objective-C. Большинство инструментов, которые в настоящее время хорошо работают с Objective-C, работают над улучшением их совместимости с Swift. Например, в настоящее время Фрида поддерживает [Swift bindings](https://github.com/frida/frida-swift "Frida-swift").

#### Xcode и iOS SDK

Xcode - это интегрированная среда разработки (IDE) для macOS, содержащая набор инструментов для разработки программного обеспечения, созданная Apple для разработки программного обеспечения для macOS, iOS, watchOS и tvOS. Последним выпуском на момент написания этой книги является Xcode 8, который можно загрузить [с официального веб-сайта Apple] (https://developer.apple.com/xcode/ide/ "Apple Xcode IDE").

IOS SDK (Software Development Kit), ранее известный как iPhone SDK, представляет собой набор для разработки программного обеспечения, созданный Apple для разработки собственных приложений для iOS. Последний выпуск на момент написания этой книги - это iOS 10 SDK, и он может быть [загружен с официального веб-сайта Apple] (https://developer.apple.com/ios/ "Apple iOS 10 SDK").

#### Уитилиты

- [Class-dump by Steve Nygard](http://stevenygard.com/projects/class-dump/) - это утилита командной строки для просмотра информации о среде выполнения Objective-C, хранящейся в файлах Mach-O (Mach object). Инструмент генерирует объявления для классов, категорий и протоколов.

- [Class-dump-z](https://code.google.com/archive/p/networkpx/wikis/class_dump_z.wiki) - это переписанный с нуля class-dump на C++, избегая использования динамических вызовов. Удаление этих ненужных вызовов делает class-dump-z почти в 10 раз быстрее, чем его предщественник.

- [Class-dump-dyld by Elias Limneos](https://github.com/limneos/classdump-dyld/) позволяет копировать и извлекать символы непосредственно из общего кэша, устраняя необходимость сначала извлекать файлы. Он может генерировать файлы заголовков из бинарных файлов приложений, библиотек, фреймворков, пакетов или всего dyld_shared_cache. Можно также выгрузить весь dyld_shared_cache или подкаталоги рекурсивно.

- [MachoOView]( https://sourceforge.net/projects/machoview/) - это полезный визуальный браузер файлов Mach-O, который также позволяет редактировать бинарные ARM файлы.

- otool - инструмент для отображения определенных частей объектных файлов или библиотек. Он понимает как файлы Mach-O, так и универсальные форматы файлов.

#### Библиотеки обратного проектирования

[Radare2](http://rada.re/r/) является библиотекой для обратного проектирования и анализа. Он построен вокруг дизассемблера Capstone, ассемблера Keystone и механизма эмуляции процессора Unicorn. Radare2 поддерживает двоичные файлы iOS и множество полезных функций iOS, таких как собственный анализатор Objective-C и отладчик iOS.

#### Коммерческие дизассемблеры

IDA Pro может работать с двоичными файлами iOS и имеет встроенный отладчик iOS. IDA признается золотым стандартом для интерактивного статического анализа на основе графического интерфейса, но это не дешево. Для более экономичного инженера Hopper предлагает аналогичные функции статического анализа.

### Обратное проектирование приложений в iOS

Процесс обратного проектирования в iOS - это компот. С одной стороны, приложения, сделанные на Objective-C и Swift, можно легко разбирать. В Objective-C объектные методы вызываются с помощью динамических указателей функций, называемых «селекторами», которые находятся по имени во время выполнения. Преимущество этого подхода заключается в том, что эти имена должны оставаться нетронутыми в финальном бинарном файле, что делает дезассемблированный код более читаемым. К сожалению, это также приводит к тому, что в дизассемблере нет прямых перекрестных ссылок между методами, и создание графа потока управления является сложной задачей.

В этом руководстве мы расскажем о статическом и динамическом анализе и инструментах. В этой главе мы ссылаемся на OWASP UnCrackable App для iOS, поэтому загрузите проект из репозитория MSTG, если вы планируете выполнять эти примеры.

#### Статический анализ

#### Получение IPA файла из OTA линка дистрибуции

Во время разработки, приложения иногда предоставляются тестировщикам через распространение по воздуху (OTA). В этом случае вы получите ссылку itms-services, примерно такую:

```shell
itms-services://?action=download-manifest&url=https://s3-ap-southeast-1.amazonaws.com/test-uat/manifest.plist
```

Вы можете использовать [ITMS services asset downloader](https://www.npmjs.com/package/itms-services) чтобы загрузить IPS через OTA ссылку. Установите через npm таким образом:

```shell
npm install -g itms-services
```

Сохраните файл IPA локально, написва следующую команду:

```shell
# itms-services -u "itms-services://?action=download-manifest&url=https://s3-ap-southeast-1.amazonaws.com/test-uat/manifest.plist" -o - > out.ipa
```

##### Восстановление файла IPA из установленного приложения

###### На джейлбрейк устройствах

Вы можете использовать [IPA Installer Console](https://cydia.saurik.com/package/com.autopear.installipa/ "IPA Installer Console"), написанную Saurik'ом, для восстановления IPA из приложений, установленных на устройстве. Для этого установите `IPA Installer Console` через Cydia. Затем, войдите через ssh на устройство и найдите идентификатор пакета целевого приложения. Например:

```shell
iPhone:~ root# ipainstaller -l
com.apple.Pages
com.example.targetapp
com.google.ios.youtube
com.spotify.client
```

Сгенерируйте файл IPA, используя следующую команду:

```shell
iPhone:~ root# ipainstaller -b com.example.targetapp -o /tmp/example.ipa
```

###### На неджейлбрейк устройствах

Если приложение доступно в iTunes, вы можете восстановить IPA на MacOS, используя простые шаги:

- Загрузите приложение в iTunes
- Перейдите в свою библиотеку приложений iTunes
- Щелкните правой кнопкой мыши приложение и выберите показать в Finder

#### Дамп расшифрованных бинарников

Помимо подписи кода, приложения, распространяемые через магазин приложений, также защищены с помощью системы Apple FairPlay DRM. Эта система использует асимметричную криптографию, чтобы гарантировать, что любое приложение (включая бесплатные приложения), полученное из магазина приложений, выполняется только на определенном устройстве, которое одобрено для запуска. Ключ дешифрования уникален для устройства и записывается в процессор. На данный момент единственный способ получить дешифрованный код из приложения с расшифровкой FairPlay - это копирование его из памяти во время работы приложения. На устройстве с джейлбрейком это можно сделать с помощью инструмента Clutch, который входит в стандартный репозиторий Cydia [2]. Используйте Clutch в интерактивном режиме, чтобы получить список установленных приложений, расшифровать их и упаковать в файл IPA:

```shell
# Clutch -i
```

**Примечание:** Только приложения, распространяемые через AppStore, защищены с помощью FairPlay DRM. Если вы получили свое приложение, скомпилированное и экспортированное непосредственно из Xcode, вам не нужно расшифровывать его. Самый простой способ - загрузить приложение в Hopper и проверить, правильно ли оно было дизассемблировано. Вы также можете проверить это с помощью otool:

```shell
# otool -l yourbinary | grep -A 4 LC_ENCRYPTION_INFO
```

Если вывод содержит поля cryptoff, cryptsize и cryptid значит бинарник защифрован. Если результат команды пустой- это значит, что бинарь незащифрован. **Запомните** необходимо использовать otool на бинарный файл, а не на файл IPA.

#### Получение базовой информации, используя Class-dump и дизассемблер Hopper

Инструмент Class-dump может быть использован для получения информации о методах в приложении. Примеры ниже используют [Damn Vulnerable iOS Application]( http://damnvulnerableiosapp.com/). Наш бинарник является, так называемым толстым бинарным файлом, это значит что он может быть использован как на 32 так и на 64-битных платформах:

```shell
$ unzip DamnVulnerableiOSApp.ipa

$ cd Payload/DamnVulnerableIOSApp.app

$ otool -hv DamnVulnerableIOSApp

DamnVulnerableIOSApp (architecture armv7):
Mach header
      magic cputype cpusubtype  caps    filetype ncmds sizeofcmds      flags
   MH_MAGIC     ARM         V7  0x00     EXECUTE    38       4292   NOUNDEFS DYLDLINK TWOLEVEL WEAK_DEFINES BINDS_TO_WEAK PIE

DamnVulnerableIOSApp (architecture arm64):
Mach header
      magic cputype cpusubtype  caps    filetype ncmds sizeofcmds      flags
MH_MAGIC_64   ARM64        ALL  0x00     EXECUTE    38       4856   NOUNDEFS DYLDLINK TWOLEVEL WEAK_DEFINES BINDS_TO_WEAK PIE
```

Подметим, что название архитектуры для 32 битной разрядности `armv7`, а также  `arm64`. Данный архитектурный прием позволяет распространять одно приложение для всех устройств. Для того, чтобы проанализировать приложение, используя class-dump нам необходимо создать, так называемый тонкий бинарник, который создан только для одной архитектуры:

```shell
iOS8-jailbreak:~ root# lipo -thin armv7 DamnVulnerableIOSApp -output DVIA32
```

После этого мы можем продолжить работу с class-dump:

```shell
iOS8-jailbreak:~ root# class-dump DVIA32

@interface FlurryUtil : ./DVIA/DVIA/DamnVulnerableIOSApp/DamnVulnerableIOSApp/YapDatabase/Extensions/Views/Internal/
{
}
+ (BOOL)appIsCracked;
+ (BOOL)deviceIsJailbroken;
```

Обратите внимание на знак плюса, который значит что это метод класса, возвращающий переменную типа BOOL. Знак минуса ниформирует о том, что это метод непосредственно объекта класса. Пожалуйста, перейдите к следующим секциям, чтобы лучше понять разницу.

Вы можете с легкостью дезассемблировать приложение, используя [Hopper Disassembler](https://www.hopperapp.com/). Все эти шаги будут выполнены автоматически и вы сможете посмотреть дезассемблированный бинарник и информацию о классах.

Следующая команда показывает список общих библиотек:

```shell
$ otool -L <binary>
```

#### Отладка

Дебаг на iOS, в основном, реализован через Mach IPC. Чтобы "прикрепиться" к целевому процессу, процесс отладчика вызывает функцию `task_for_pid()` с идентификатором целевого процесса и получает порт Mach. Отладчик после этого регистрируется как получатель сообщений о возникших исключениях(ошибках) и начинает обрабатывать любые исключения, возникающией в целевом приложении. Вызовы Mach IPC используются для таких целей как, приостановка целевого приложения и чтение/запись значений регистров и вирутальной памяти.

Даже несмотря на то, что ядро XNU реализует системный вызов `ptrace()`, некоторая его функциональность была удалена, включая функцию читать и писать значения регистров и значения памяти. Тем не менее, `ptrace()` используется стандартными отладчиками `lldb` и `gdb` ограниченно. Некоторые отладчики, включая Radare2, не используют `ptrace` вообще.

##### Использование LLDB

iOS поставляется с консольным приложением, debugserver, которое позволяет воспользоваться удаленной отладкой с использованием lldb или gdb. По умолчанию, debugserver не может прикрепляться к произвольным процессам (обычно, он используется для отладки собственных приложений, разработанных в Xcode). Чтобы включить отладку сторонних приложений, право на получение task_for_pid должно быть добавлено в исполняемый файл debugserver. Самый простой способ сделать это- добавление права в [исполняемый файл debugserver, поставляемый с Xcode](http://iphonedevwiki.net/index.php/Debugserver "Debug Server on the iPhone Dev Wiki").

Чтобы получить исполняемый файл смонтируйте следующий DMG образ:

```shell
/Applications/Xcode.app/Contents/Developer/Platforms/iPhoneOS.platform/ DeviceSupport/<target-iOS-version>//DeveloperDiskImage.dmg
```

Вы найдете исполняемый файл debugserver в директории /usr/bin/ на смонтированном томе, скопируйте его во временную директорию.После этого, создайте файл entitlements.plist со следующим содержимым:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/ PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>com.apple.springboard.debugapplications</key>
	<true/>
	<key>run-unsigned-code</key>
	<true/>
	<key>get-task-allow</key>
	<true/>
	<key>task_for_pid-allow</key>
	<true/>
</dict>
</plist>
```

Примените entitlement через codesign:

~~~
codesign -s - --entitlements entitlements.plist -f debugserver
~~~

Скопируйте измененный бинарный файл в любую директорию на тестовом устройстве (обратите внимание, что следующие примеры используют usbmuxd для перенаправления локального порта через USB).

```shell
$ ./tcprelay.py -t 22:2222
$ scp -P2222 debugserver root@localhost:/tmp/
```

Вы можете прикреплять debugserver к любому процессу, выполняемому на устройстве.

```shell
VP-iPhone-18:/tmp root# ./debugserver *:1234 -a 2670
debugserver-@(#)PROGRAM:debugserver  PROJECT:debugserver-320.2.89
 for armv7.
Attaching to process 2670...
```

#### Cycript и Cynject

Cydia Substrate (раньше называемая MobileSubstrate) является де-факто стандартной библиотекой для разработки патчей времени исполнения(“Cydia Substrate extensions”) на iOS. Он поставляется с Cynject, инструментом, поддерживающим инъекции кода для С. Cycript- это скриптовой язык, разработанный Jay Freeman (saurik). Cycript осуществляет инъекцию JavaScriptCore VM в исполняемый процесс. После этого пользователь может управлять процессом, используя гибридный синтаксис Objective-C++ и JavaScript через интерактивную консоль Cycript. Также возможно осуществлять доступ и инициализировать объекты классов Objective-C в исполняющемся процесе. Некоторые примеры использования Cycript приведены в главе iOS.

Прежде всего, необходимо скачать, распаковать и установить SDK.

```shell
#on iphone
$ wget https://cydia.saurik.com/api/latest/3 -O cycript.zip && unzip cycript.zip
$ sudo cp -a Cycript.lib/*.dylib /usr/lib
$ sudo cp -a Cycript.lib/cycript-apl /usr/bin/cycript
```
Чтобы создать интерактивную оболочку cycript, вы можете запустить “./cyript” или просто “cycript”, если он находится в вашей глобальной переменной PATH.

```shell
$ cycyript
cy#
```

Чтобы произвести инъекцию в запущенный процесс, в первую очередь необходимо найти идентификатор процесса(PID). Вы можете выполнить "cycript -p" с указанием PID того процесса, куда хотите произвести инъекцию. Чтобы продемонстрировать мы произведем инъекцию в SpringBoard.

```shell
$ ps -ef | grep SpringBoard
501 78 1 0 0:00.00 ?? 0:10.57 /System/Library/CoreServices/SpringBoard.app/SpringBoard
$ ./cycript -p 78
cy#
```

Мы осуществили инекцию в SpringBoard, давайте попробуем вызвать сообщение оповещения на SpringBoard, используя cycript. 		

```shell
cy# alertView = [[UIAlertView alloc] initWithTitle:@"OWASP MSTG" message:@"Mobile Security Testing Guide"  delegate:nil cancelButtonitle:@"OK" otherButtonTitles:nil]
#"<UIAlertView: 0x1645c550; frame = (0 0; 0 0); layer = <CALayer: 0x164df160>>"
cy# [alertView show]
cy# [alertView release]
```
![Cycript Alert Sample](Images/Chapters/0x06c/cycript_sample.png)

Узнайте папку документа, используя cycript:

```shell
cy# [[NSFileManager defaultManager] URLsForDirectory:NSDocumentDirectory inDomains:NSUserDomainMask][0]
#"file:///var/mobile/Containers/Data/Application/A8AE15EE-DC8B-4F1C-91A5-1FED35212DF/Documents/"
```

Получайте класс делегата приложения, используя следующую команду:

```shell
cy# [UIApplication sharedApplication].delegate
```

Команда [[UIApp keyWindow] recursiveDescription].toString() возвращает иерархию view для keyWindow. Описание каждого subview и sub-subview для keyWindow будет показано, а отступ будет отражать взаимоотношения каждого view. Например, UILabel, UITextField и UIButton являются subviews UIView.

```shell
cy# [[UIApp keyWindow] recursiveDescription].toString()
`<UIWindow: 0x16e82190; frame = (0 0; 320 568); gestureRecognizers = <NSArray: 0x16e80ac0>; layer = <UIWindowLayer: 0x16e63ce0>>
   | <UIView: 0x16e935f0; frame = (0 0; 320 568); autoresize = W+H; layer = <CALayer: 0x16e93680>>
   |    | <UILabel: 0x16e8f840; frame = (0 40; 82 20.5); text = 'i am groot!'; hidden = YES; opaque = NO; autoresize = RM+BM; userInteractionEnabled = NO; layer = <_UILabelLayer: 0x16e8f920>>
   |    | <UILabel: 0x16e8e030; frame = (0 110.5; 320 20.5); text = 'A Secret Is Found In The ...'; opaque = NO; autoresize = RM+BM; userInteractionEnabled = NO; layer = <_UILabelLayer: 0x16e8e290>>
   |    | <UITextField: 0x16e8fbd0; frame = (8 141; 304 30); text = ''; clipsToBounds = YES; opaque = NO; autoresize = RM+BM; gestureRecognizers = <NSArray: 0x16e94550>; layer = <CALayer: 0x16e8fea0>>
   |    |    | <_UITextFieldRoundedRectBackgroundViewNeue: 0x16e92770; frame = (0 0; 304 30); opaque = NO; autoresize = W+H; userInteractionEnabled = NO; layer = <CALayer: 0x16e92990>>
   |    | <UIButton: 0x16d901e0; frame = (8 191; 304 30); opaque = NO; autoresize = RM+BM; layer = <CALayer: 0x16d90490>>
   |    |    | <UIButtonLabel: 0x16e72b70; frame = (133 6; 38 18); text = 'Verify'; opaque = NO; userInteractionEnabled = NO; layer = <_UILabelLayer: 0x16e974b0>>
   |    | <_UILayoutGuide: 0x16d92a00; frame = (0 0; 0 20); hidden = YES; layer = <CALayer: 0x16e936b0>>
   |    | <_UILayoutGuide: 0x16d92c10; frame = (0 568; 0 0); hidden = YES; layer = <CALayer: 0x16d92cb0>>`
```

##### Подмена(хук) нативных функций и методов Objective-C

- Установите приложение, в котором хотите применить хуки.
- Запустите приложение и убедитесь, что оно находится в состоянии foreground (не должно находится в состоянии pause).
- Узнайте PID приложения, используя команду: `ps ax | grep App`.
- Осуществите внедрение в приложение, написав: `cycript -p PID`.
- Интерпретатор Cycript будет предоставлен, в случае успеха. Вы можете получить сущность приложения, использовав синтаксис Objective-C `[UIApplication sharedApplication]`.

    ```
    cy# [UIApplication sharedApplication]
    cy# var a = [UIApplication sharedApplication]
    ```

- Чтобы получить делегат приложения:

    ```
    cy# a.delegate
    ```

- Для печати методов класса AppDelegate:

    ```
    cy# printMethods (“AppDelegate”)
    ```

#### Установка Frida

[Frida](https://www.frida.re "frida") - библиотека инструментирования времени исполнения, которая позволяет осуществлять инъекции кода JavaScript, или же части ващей собственной библиотеки в нативные приложения для Android и iOS. Если вы уже читали разделы про Android, вы должны быть частично знакомы с этим инструментом.

В противном случае, вам необходимо установить пакет Frida Python на вашу хост машину:

```shell
$ pip install frida
```

Чтобы подключить Frida к приложению iOS, необходим способ инъекции среды выполнения Frida в приложение. Это легко сделать на джейлбрейк устройстве: просто установите frida-server через Cydia. После этого, frida-server будет автоматически выполняться с правами root, позволяя вам с легкостью проводить инъекции в любой процесс.

Запустите Cydia и добавьте репозиторий Frida, нажав Manage -> Sources -> Edit -> Add и введя `https://build.frida.re`. После этого вы сможете найти и установить пакет Frida.

Подключите ваше устройство через USB и убедитесь, что Frida работает, написав команду `frida-ps`. Должен вернуться список процессов, запущенных на устройстве:

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

Мы продемонстрируем чуть больше способов использования Frida ниже, но сначала давайте взглянем на то что необходимо сделать, если вы вынуждены работать с неджейлбрейкнутым устройством.

### Динамический анализ на неджейлбрейкнутом устройстве

#### Автоматическая переупаковка с использованием Objection

[Objection](https://github.com/sensepost/objection "Objection") - это набор инструментов, основанный на Frida, используется для изучения среды исполнения. Основное преимущество - тестирование на неджейлбрейк устройствах. Это осуществляется с помощью библиотеки `FridaGadget.dylib`, которая автоматизирует переупаковку. Детальное объяснение мануалного процесса переупаковки и переподписи можно найти в разделе ниже. Мы не будем детально разбирать Objection в данном руководстве, так как исчерпывающую информацию можно найти на официальных [вики страницах](https://github.com/sensepost/objection/wiki "Objection - Documentation").

#### Мануальная(ручная) переупаковка

Если у вас нет доступа к джейлбрейк-устройству, вы можете пропатчить и переупаковать целевое приложение для загрузки динамической библиотеки при запуске. Таким образом, вы можете настроить приложение и сделать практически все, что вам нужно для динамического анализа (конечно, вы не можете вырваться из песочницы таким образом, но вам это будет необязательно). Однако этот метод работает только в том случае, если бинарное приложение не является зашифрованным через FairPlay (т.е. полученным из магазина приложений).

Благодаря запутанной системе подписи кода и профилирования Apple, переподписывание приложения является более сложным, чем вы  могли ожидать. iOS не запускает приложение, если вы точно не получите provisioning profile и code signature header. Это требует изучения многих концепций - типов сертификатов, идентификаторов пакетов, идентификаторов приложений, идентификаторов команд и способов их подключения к инструментам сборки Apple. Достаточно сказать, что заставить ОС запускать двоичный файл, который не был собран по умолчанию (через Xcode), может быть сложным процессом.

Мы будем использовать `optool`, инструменты сборки Apple и некоторые команды оболочки. Наш способ был вдохновлен [проектом Swizzler, автор: Vincent Tan](https://github.com/vtky/Swizzler2/ "Swizzler"). [Группа NCC](https://www.nccgroup.trust/au/about-us/newsroom-and-events/blogs/2016/october/ios-instrumentation-without-jailbreak/ "NCC blog - iOS instrumentation without jailbreak"), где описан алтернативный метод переупаковки.

Чтобы повторить перечисленные ниже шаги, загрузите [UnCrackable iOS App Level 1](https://github.com/OWASP/owasp-mstg/tree/master/Crackmes/iOS/Level_01 "Crackmes - iOS Level 1") из репозитория OWASP Mobile Testing Guide. Наша цель - произвести инъекцию `FridaGadget.dylib` в приложение UnCrackable во время запуска, чтобы мы могли инструментировать его с помощью Frida.

> Обратите внимание, что следующие шаги применимы только к macOS, поскольку Xcode доступен только для macOS.

#### Получение Provisioning Profile и сертификата разработчика

*Provisioning profile* является файлом plist, подписанным Apple. Он одобряет ваш сертификат подписи кода на одном или нескольких устройствах. Другими словами, это означает, что Apple явно разрешает вашему приложению запускаться по определенным причинам, например отладка на выбранных устройствах(в профиле разработки). Provisioning profile также включает *entitlements*, предоставленные вашему приложению. *Сертификат* содержит закрытый ключ, который вы будете использовать для подписи.

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

Apple предоставит вам бесплатный профиль разработки, даже если вы не являетесь платящим разработчиком(с недавних пор - замечание переводчика). Вы можете получить профиль с помощью Xcode и обычной учетной записи Apple: просто создайте пустой проект iOS и извлеките `embedded.mobileprovision` из контейнера приложений, который находится в подкаталоге Xcode вашего домашнего каталога:`~/Library/Developer/Xcode/DerivedData/<ProjectName>/Build/Products/Debug-iphoneos/<ProjectName>.app/`. [Пост в блоге NCC "iOS instrumentation without jailbreak"] (https://www.nccgroup.trust/au/about-us/newsroom-and-events/blogs/2016/october/ios-instrumentation-without-jailbreak/ "iOS instrumentation without jailbreak") подробно объясняет этот процесс.

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

Обратите внимание на идентификатор приложения, который представляет собой комбинацию идентификатора команды (LRUD9L355Y) и идентификатора пакета (sg.vantagepoint.repackage). Этот provisioning profile действителен только для приложения, имеющего этот идентификатор приложения. Также важен пункт «get-task-allow» - если установлено значение «true», другим приложениям(таким как сервер отладки) разрешено присоединяться к приложению(следовательно, этот ключ будет установлен на «false» в distribution profile).

#### Другие подготовительные действия

Чтобы наше приложение загрузило дополнительную библиотеку при запуске, нам нужно каким-то образом вставить дополнительную команду загрузки в заголовок Mach-O основного исполняемого файла. [Optool] (https://github.com/alexzielenski/optool "Optool") может автоматизировать этот процесс:

```shell
$ git clone https://github.com/alexzielenski/optool.git
$ cd optool/
$ git submodule update --init --recursive
$ xcodebuild
$ ln -s <your-path-to-optool>/build/Release/optool /usr/local/bin/optool
```

Мы также будем использовать [ios-deploy] (https://github.com/phonegap/ios-deploy "ios-deploy") - инструмент, позволяющий отлаживать и развертывать приложения iOS без Xcode:

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

Наконец, мы используем `codesign` для повторной подписи двух двоичных файлов. Вместо «8004380F331DCA22CC1B47FB1A805890AE41C938» вам нужно использовать свой идентификатор подписи, который вы можете вывести, выполнив команду `security find-identity -v`.

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

Когда что-то пойдет не так (и это обычно происходит), наиболее вероятными причинами являются несоответствия между provisioning profile и code signing header. Чтение [официальной документации](https://developer.apple.com/library/content/documentation/IDEs/Conceptual/AppDistributionGuide/MaintainingProfiles/MaintainingProfiles.html "Maintaining Provisioning Profiles") поможет понять процесс подписи кода. Ресурс Apple [entitlement troubleshooting page](https://developer.apple.com/library/content/technotes/tn2415/_index.html "Entitlements Troubleshooting ") также очень полезен.


### Трассировка методов с использованием Frida

Перехват методов Objective-C - полезный метод тестирования безопасности iOS. Например, вас могут заинтересовать операции хранения данных или сетевые запросы. В следующем примере мы напишем простой трассировщик для протоколирования запросов HTTP(S), созданных с помощью стандартных HTTP API iOS. Мы также покажем вам, как произвести инъекцию трассировщика в веб-браузер Safari.

В следующих примерах мы предположим, что вы работаете на джейлбрейк-устройстве. Если это не так, сначала необходимо выполнить шаги, описанные в предыдущем разделе, чтобы переупаковать приложение Safari.

Frida поставляется с `frida-trace`, готовым инструментом отслеживания функций. `frida-trace` принимает методы Objective-C с помощью флага -m. Вы можете передать ему wildcard `- [NSURL *]`, например, `frida-trace` будет автоматически устанавливать перехваты во всех селекторах классов` NSURL`. Мы будем использовать это, чтобы получить общее представление о том, какие библиотечные функции вызывает Safari, когда пользователь открывает URL-адрес.

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
            // Get a handle on NSString
            var NSString = ObjC.classes.NSString;

            // Obtain a reference to the NSLog function, and use it to print the URL value
            // args[2] refers to the first method argument (NSURL *url)
            var NSLog = new NativeFunction(Module.findExportByName('Foundation', 'NSLog'), 'void', ['pointer', '...']);

            // We should always initialize an autorelease pool before interacting with Objective-C APIs
            var pool = ObjC.classes.NSAutoreleasePool.alloc().init();

            try {
                // Creates a JS binding given a NativePointer.
                var myNSURL = new ObjC.Object(args[2]);

                // Create an immutable ObjC string object from a JS string object.
                var str_url = NSString.stringWithString_(myNSURL.toString());
                NSLog(str_url);
            } finally {
                pool.release();
            }
        }

    });


"""

process = frida.get_usb_device().attach("Safari")
script = process.create_script(frida_code)
script.on('message', message_callback)
script.load()

sys.stdin.read()
```

Запустите Safari на устройстве iOS. Запустите вышеуказанный скрипт Python на подключенном хосте и откройте лог устройства (мы объясним, как открыть лог устройства в следующем разделе). Попробуйте открыть новый URL-адрес в Safari; вы должны увидеть вывод Frida в логах.

![Frida Xcode Log](Images/Chapters/0x06c/frida-xcode-log.png)

Конечно, этот пример иллюстрирует только одну из вещей, которые вы можете сделать с Frida. Чтобы осмыслить весь потенциал инструмента, вы должны научиться использовать его [JavaScript API](https://www.frida.re/docs/javascript-api/ "Frida JavaScript API reference"). На сайте Frida, в разделе документации есть [руководство](https://www.frida.re/docs/ios/ "Frida Tutorial") и [примеры](https://www.frida.re/docs/examples/ios/ "Frida examples") для использования Frida в iOS.

[Frida JavaScript API reference](https://www.frida.re/docs/javascript-api/)


#### Патч приложений на React Native

Если библиотека [React Native](https://facebook.github.io/react-native "React Native") была использована для разработки, основной код приложения находится в файле `Payload/[APP].app/main.jsbundle`. В этом файле лежит JavaScript. В основном, код JavaScript минифицирован в данном файле. Используя инструмент [JStillery](https://mindedsecurity.github.io/jstillery "JStillery"), можно получить читайемый код, тем самым открывая возможность для статического анализа. [CLI version of JStillery](https://github.com/mindedsecurity/jstillery/ "CLI version of JStillery") или же локальный сервер должен быть предпочтительным выбором, вместо использования онлайн версии, иначе исходный код будет отправлен третьей стороне.

Во время установки, архив приложения распаковывается в папку `/private/var/containers/Bundle/Application/[GUID]/[APP].app`, следовательно основной JavaScript файл приложения может быть изменен здесь.

Чтобы определить точное местоположение папки с приложением, инструмент  [ipainstaller](https://cydia.saurik.com/package/com.slugrail.ipainstaller/ "ipainstaller") может быть использован следующим образом:

1. Используйте команду `ipainstaller -l`, чтобы отобразить список установленных на девайсе приложений и получить имя целевого приложения из выведенного списка.
2. Используйте команду `ipainstaller -i [APP_NAME]`, чтобы отобразить информацию о целевом приложении, включая путь до папки установки приложения и папок с данными.
3. Возьмите путь, указанный в строке, начинающейся с `Application:`.

Следующий подход может быть использован для патча файла JavaScript:

1. Переместитесь в папку с приложением.
2. Скопируйте содержимое файла `Payload/[APP].app/main.jsbundle` во временный файл.
3. Используйте `JStillery` для облагораживания и деобфускации файла.
4. Определите где код необходимо пропатчить во временном файле и сделайте это.
5. Переместите *пропатченный код* в одну строку и скопируйте его в исходный файл  `Payload/[APP].app/main.jsbundle`.
6. Закройте и перезагрузите приложение.
