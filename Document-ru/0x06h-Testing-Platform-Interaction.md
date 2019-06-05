## API платформы iOS

### Тестирование кастомных схем URL

#### Обзор

В отличие от богатых возможностей межпроцессного взаимодействия на системах Android, iOS предлагает несколько опций для организации связи между приложениями. По сути, не существует возможности для приложений обмениваться данными напрямую. Вместо этого Apple предлагает [два типа косвенной коммуникации](https://developer.apple.com/library/content/documentation/iPhone/Conceptual/iPhoneOSProgrammingGuide/Inter-AppCommunication/Inter-AppCommunication.html): передача файла через AirDrop и использование URL схем(schemes).

Специализированные схемы URL позволяют приложениям осуществлять коммуникацию через нестандартный протокол. Приложению необходимо заявить о поддержке определенной(ых) схемы URL, после чего обрабатывать поступающие запросы, использующие указанную схему. После того как схема зарегистрирована, другие приложения могут открывать искомое, передав необходиые параметры через URL можно открыть приложение, используя метод `openURL`.

Проблемы безопасности возникают, когда приложение, обрабатывающее созданную URL схему, не уделяет требуемое внимание проверке параметров и самого URL, также оказывает влияние тот факт, что пользователю не предлагается подтвердить исполнение важного действия, перед тем как оно выполнится.

Один из примеров - [баг в приложении Skype](http://www.dhanjani.com/blog/2010/11/insecure-handling-of-url-schemes-in-apples-ios.html), обнаруженный в 2010: Приложение Skype зарегистрировало обработчик URL схемы  `skype://`, которая позволяла другим приложениям вызывать звонок другим пользователям Skype или же звонок на прямые номера. К сожалению, Skype не спрашивал пользователя о разрешении выполнения такого звонка, так что любое приложение могло звонить на любые номера без уведомления пользователя.

Злоумышленники использовали эту уязвимость, вставив невидимый `<iframe src="skype://xxx?call"></iframe>` (где `xxx` было заменено премиум номером), так что любой пользователь Skype, оказавшийся на вредоносном сайте звонил на премиальный номер.

#### Статический анализ

Первым делом необходимо узнать, зарегистрировало ли приложение нестандартные URL схемы, для этого необходимо посмотреть файл `Info.plist` в папке приложения. Для того чтобы посмотреть зарегистрированные обработчики протоколов нужно просто открыть проект в Xcode, перейте в раздел `Info`, и открыть секцию `URL Types`, показанную на скриншоте ниже.

![Document Overview](Images/Chapters/0x06h/URL_scheme.png)

Следующим шагом необходимо определить по какому принципу составляется URL, а также как он валидируется. Метод [`openURL`](https://developer.apple.com/documentation/uikit/uiapplication/1648685-openurl?language=objc) отвечает за обработку пользовательских URL. Обратите внимание на контрмеры: как URL проверяются(какой ввод принимают, в целом) и необходимо ли разрешение пользователя для того чтобы воспользоваться нестандартной URL схемой?

В скомпилированном приложении, зарегистрированные обработчики протоколов можно найти в файле `Info.plist`. Чтобы найти структуру URL, посмотрите на использование ключа `CFBundleURLSchemes` используя интсрумент `strings` или `Hopper`:

``shell
$ strings <yourapp> | grep "myURLscheme://"
```

Вам необходимо тщательно проверять любой URL перед его исполнением. Вы можете ввести списки, содержашие приложения, которым разрешено открывать искомое приложение, используя определенную URL схему. Также отличной стратегией является запрос подтверждения пользователя касательно открытия URL и соответсвенно выполнения действия, которое будет произведено при выполнении данного протокола.

#### Динамический анализ

После того как вы определили какие схемы используются приложением, откройте эти URL, используя Safari, и посмотрите на поведение.

Если приложение осуществляет парсинг URL по частям, то вы можете попробовать фаззинг входных данных, чтобы определить возможные баги повреждения памяти. Для это можно использовать [IDB](https://www.idbtool.com/ "IDBTool"):



- Запустите IDB, подключитесь к своему устройству и выберете целевое приложение. Можете найти подробности в [IDB documentation](https://www.idbtool.com/documentation/setup.html).
- Откройте секцию `URL Handlers`. В `URL schemes`, кликните на `Refresh` , и слева вы найдете полный список всех нестандартных схемы в тестируемом приложении. Вы можете загрузить эти схемы, нажав на `Open`, находящуюся справа. Просто открывая пустую схему URI (например, открывая `myURLscheme://`), вы можете обнаружить скрытую функциональность (например, окно дебага) и обойти локальную аутентификацию.
- Чтобы обнаружить есть ли баги в нестандартных схемах URI, попробуйти применить технику фуззинга. В секции `URL Handlers` зайдите во вкладку `Fuzzer`. Слева выведутся стандартные варианты IDB. [FuzzDB](https://github.com/fuzzdb-project/fuzzdb) предлагает фуззинг словари. Как только ваши данные готовы, зайдите во вкладку `Fuzz Template` на нижней-левой панеле и определите шаблон. Используйте `$@$`, чтобы задать точки инъекции, например:

``shell
myURLscheme://$@$
```
Пока URL схемы проходят фуззинг, посмотрите логи (в Xcode, перейдите `Window -> Devices ->` *нажмите на своей устройство* `->` *нижняя консоль содержит логи*) чтобы посмотреть результат каждой попытки. История, примененных вариантов находится справой стороны вкладки `Fuzzer` в IDB.

Needle может быть использован для тестирования нестандартных схем URL, ручной фуззинг может быть осуществлен для определения ошибок валидации ввода и ошибок повреждения памяти. Нижеописанный модуль Needle необходимо использовать для такого типа атак:

```
[needle] >
[needle] > use dynamic/ipc/open_uri
[needle][open_uri] > show options

  Name  Current Value  Required  Description
  ----  -------------  --------  -----------
  URI                  yes       URI to launch, eg tel://123456789 or http://www.google.com/

[needle][open_uri] > set URI "myapp://testpayload'"
URI => "myapp://testpayload'"
[needle][open_uri] > run

```

### Тестирование iOS WebViews

#### Обзор

WebViews являются встроенными в приложение компонентами браузера для отображения интерактивного веб контента. Они могут быть использованы для встраивания веб контента непосредственно в интрефейс приложения.


iOS WebViews поддерживают исполнение JavaScript по умолчанию, таким образом инъекции скриптов и атаки XSS могут быть применены. Начиная с версии iOS 7.0, Apple также представила API, которые разрешают коммуникацию между средой исполнения  JavaScript в WebView и нативным Swift или Objective-C приложением. Если эти API были использованы неосторожно, важная функциональность может быть доступна злоумышленникам, которые умудрились осуществить инъекцию вредоносного скрипта в WebView (например, через удачную XSS атаку).

Помимо потенциальной инъекции скриптов, существует другая фундаментальная проблема с безопасностью WebViews: библиотеки WebKit, поставляемые с iOS не обновляются по-одиночке, как, например Safari. Более того, новые уязвимости, обнаруженные в WebKit остаются эксплуатируемыми до следующего полного обновления iOS [#THIEL].

WebViews поддерживают различные URL схемы, например такие tel. Определение [tel:// схемы может быть отключено](https://developer.apple.com/library/content/featuredarticles/iPhoneURLScheme_Reference/PhoneLinks/PhoneLinks.html "Phone Links on iOS") на странице HTML и после этого никогда не будет интерпретироваться в WebView.

#### Статический анализ

Посмотрите на использование следующих компонентов, которые реализуют WebViews:

- [UIWebView](https://developer.apple.com/reference/uikit/uiwebview "UIWebView reference documentation") (для iOS 7.1.2 и старше)
- [WKWebView](https://developer.apple.com/reference/webkit/wkwebview "WKWebView reference documentation") (для iOS  8.0 и старше)
- [SFSafariViewController](https://developer.apple.com/documentation/safariservices/sfsafariviewcontroller)

`UIWebView` устарел и не должен использоваться. Убедитесь что используется либо `WKWebView` или `SafariViewController` для включения веб контента в приложение:

- `WKWebView` - это подходящий выбор для расширения функциональности приложения, контролируя отображаемый контент (например, предотвращение перехода пользователя на произвольные URL), а также для кастомизации.
- `SafariViewController` должен использоваться для предоставления стандартного опыта использования просмотра веб страниц. Обращаем внимание, что `SafariViewController` делится файлами кукис и другими данными веб сайтов с Safari.

`WKWebView` предоставляется с несколькими преимуществами безопасности, нежели `UIWebView`:

- Свойство `JavaScriptEnabled` может быть использовано, чтобы полностью выключить JavaScript в WKWebView. Это предотвращает все векторы атак с инъекцией скриптов.
- `JavaScriptCanOpenWindowsAutomatically` может быть использовано для предотвращения JavaScript от открытия новых окон, таких как поп-апы.
- Свойство `hasOnlySecureContent` может быть использовано для верификации ресурсов, загруженных WebView, на предмет загрузки их через защищенный канал.
- WKWebView реализуют рендеринг в другом процессе, так что ошибки повреждения памяти не будут влиять на основной процесс приложения.

##### Конфигурация JavaScript

Лучшей практикой считается отключение JavaScript в `WKWebView`, если же это не требуется специально. Следующий код показывает пример использования:

```objc
#import "ViewController.h"
#import <WebKit/WebKit.h>
@interface ViewController ()<WKNavigationDelegate,WKUIDelegate>
@property(strong,nonatomic) WKWebView *webView;
@end

@implementation ViewController

- (void)viewDidLoad {

    NSURL *url = [NSURL URLWithString:@"http://www.example.com/"];
    NSURLRequest *request = [NSURLRequest requestWithURL:url];
    WKPreferences *pref = [[WKPreferences alloc] init];

    //Disable javascript execution:
    [pref setJavaScriptEnabled:NO];
    [pref setJavaScriptCanOpenWindowsAutomatically:NO];

    WKWebViewConfiguration *conf = [[WKWebViewConfiguration alloc] init];
    [conf setPreferences:pref];
    _webView = [[WKWebView alloc]initWithFrame:CGRectMake(self.view.frame.origin.x,85, self.view.frame.size.width, self.view.frame.size.height-85) configuration:conf] ;
    [_webView loadRequest:request];
    [self.view addSubview:_webView];

}
```

JavaScript не может быть отключен в `SafariViewController` и это основная причина, почему вы должны рекомендовать использование `WKWebView`, когда целью является расширение графического интерфейса пользователя.

##### Незащищенность нативных объектов

И `UIWebView` и `WKWebView` предоставляют способы коммуникция WebView и нативного приложения.
Любая важная информация или же нативная функциональность является доступной движку WebView JavaScript, ровно так же как и вредоносному JavaScript, исполняемому в WebView.

###### UIWebView

С iOS 7, библиотека JavaScriptCore предоставляет обертку Objective-C для движка WebKit JavaScript.
Это дает возможность исполнять JavaScript из Swift и Objective-C, ровно также как Objective-C и Swift объекты доступны из среды исполнения JavaScript.

Среда исполнения JavaScript представлена объектом `JSContext`. Посмотрите на код, который мапит нативные объекты в `JSContext`, ассоциированные с WebView. В Objective-C, `JSContext`, ассоциированный с `UIWebView` можно получить следующим образом:

``objective-c
[webView valueForKeyPath:@"documentView.webView.mainFrame.javaScriptContext"]
``

- Блоки Objective-C. Когда блок Objective-C присвоен идентификатору в JSContext, JavaScriptCore автоматически оборачивает блок в функцию JavaScript;
- Протокол JSExport: Свойства, методы объектов и классов, объявленные в протоколе, унаследованном от JSExport, мапяться в объекты JavaScript, которые доступны в коде JavaScript. Модификации объектов, которые происходят в среде JavaScript также отражаются и на нативную среду.

Обратите внимание, что только члены класса, объявленные в протоколе `JSExport` доступны для кода JavaScript.

###### WKWebView

С другой стороны `UIWebView`, не позволяет прямой доступ к контексту `JSContext` в `WKWebView`. Вместо этого, коммуникация реализована через систему сообщений. Код JavaScript может посылать сообщения обратно в нативное приложение, используя метод `postMessage`:

```javascript
window.webkit.messageHandlers.myHandler.postMessage()
```

API `postMessage` автоматически сериализует объекты JavaScript в нативные Objective-C или Swift. Обработчик сообщения настроен на использование метода `addScriptMessageHandler`.


##### Добавление локальных файлов

WebViews могут загружать удаленный контент или же локальный, находящийся в папке приложения. Если локальный файл загружается, то пользователь не должен иметь возможности модифицировать его имя, путь или же само его содержимое.

Проверьте исходный код на наличие в нем WebViews, при нахождении использования посмотрите загружает ли этот элемент локальные файлы(`example_file.html` в примере ниже).

```objc
- (void)viewDidLoad
{
    [super viewDidLoad];
    WKWebViewConfiguration *configuration = [[WKWebViewConfiguration alloc] init];

    self.webView = [[WKWebView alloc] initWithFrame:CGRectMake(10, 20, CGRectGetWidth([UIScreen mainScreen].bounds) - 20, CGRectGetHeight([UIScreen mainScreen].bounds) - 84) configuration:configuration];
    self.webView.navigationDelegate = self;
    [self.view addSubview:self.webView];

    NSString *filePath = [[NSBundle mainBundle] pathForResource:@"example_file" ofType:@"html"];
    NSString *html = [NSString stringWithContentsOfFile:filePath encoding:NSUTF8StringEncoding error:nil];
    [self.webView loadHTMLString:html baseURL:[NSBundle mainBundle].resourceURL];
}
```

Проверьте `baseURL` на наличие динамических параметров, которыми можно манипулировать(ведущие к включению локальных файлов).

#### Динамический анализ

Чтобы воспроизвести потенциальную атаку, произведите инъекцию вашего собственного JavaScript в WebView с перехватывающим прокси. Попробуйте получить доступ к локальному хранилищу и любым нативным методам и свойствам, которые могут быть доступны контексту JavaScript.

В реальном мире, JavaScript может быть инъекцирован через перманентную эксплуатацию XSS на стороне сервера или же реализовав атаку man-in-the-middle. Посмотрите OWASP [XSS cheat sheet](https://www.owasp.org/index.php/XSS_(Cross_Site_Scripting\)\_Prevention_Cheat_Sheet "XSS (Cross Site Scripting) Prevention Cheat Sheet"), а также главу "Тестирование сетевой коммуникации" для получения подробной информации.

### Ссылки

#### OWASP Mobile Top 10 2016

- M7 - Инъекция на стороне клиента - https://www.owasp.org/index.php/Mobile_Top_10_2016-M7-Poor_Code_Quality

#### OWASP MASVS

- V6.3: "Приложение не экспортирует чувствительные функции через настраиваемые схемы URL, если эти механизмы не защищены должным образом."
- V6.5: "JavaScript отключен в WebViews, если явно не требуется."
- V6.6: "WebViews настроены так, чтобы пропускать только минимальный набор обработчиков протоколов (в идеале поддерживается только https). Потенциально опасные обработчики, такие как file, tel и app-id отключены."
- V6.7: "Если нативные методы приложения доступны в WebView, убедитесь, что WebView только отображает JavaScript, содержащийся в пакете приложений."

#### CWE

- CWE-79 - Improper Neutralization of Input During Web Page Generation https://cwe.mitre.org/data/definitions/79.html
- CWE-939 - Improper Authorization in Handler for Custom URL Scheme

#### Информация

- [#THIEL] Thiel, David. iOS Application Security: The Definitive Guide for Hackers and Developers (Kindle Locations 3394-3399). No Starch Press. Kindle Edition.

#### Инструменты
- IDB - http://www.idbtool.com/
