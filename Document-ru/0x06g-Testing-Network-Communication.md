## Сетевые API в iOS

Почти каждое приложение iOS играет роль клиента одного или нескольких удаленных сервисов. Обычно такой сетевой обмен происходит через недоверенные сети, такие как публичные Wi-Fi, классические сетевые атаки становятся потенциальной проблемой.

Самые современные мобильные приложения используют варианты веб-сервисов, основанных на HTTP, так как эти протоколы хорошо документированы и поддерживаются. На iOS класс `NSURLConnection` предоставляет методы для загрузки URL-запросов синхронно или же асинхронно.

### Безопасность передачи данных в приложении

#### Обзор

[App Transport Security (ATS)](https://developer.apple.com/library/content/documentation/General/Reference/InfoPlistKeyReference/Articles/CocoaKeys.html "Information Property List Key Reference: Cocoa Keys")- это набор проверок, которые применяет система, когда происходит соединение с использованием [NSURLConnection](https://developer.apple.com/reference/foundation/nsurlconnection "API Reference NSURLConnection"), [NSURLSession](https://developer.apple.com/reference/foundation/urlsession "API Reference NSURLSession") и [CFURL](https://developer.apple.com/reference/corefoundation/cfurl-rd7 "API Reference CFURL") к публичным хостам. ATS включен по умолчанию в сборку приложений на iOS SDK 9 и выше.

ATS применяется только при подключении к публичным хостам. Таким образом любое соединение к IP адресу, неполным доменным именам или же к TLD на .local не защищаются ATS.

Резюмированный список [App Transport Security Requirements](https://developer.apple.com/library/content/documentation/General/Reference/InfoPlistKeyReference/Articles/CocoaKeys.html "Information Property List Key Reference: Cocoa Keys"):

- HTTP соединение запрещено.
- Сертификат X.509 имеет отпечаток SHA256 и должен быть подписан, как минимум, 2048-битным ключом RSA или же 256-битным ключом ECC(Elliptic-Curve Cryptography).
- Версия TLS(Transport Layer Security) должна быть 1.2 или выше и должна быть обеспечена поддержка PFS (Perfect Forward Secrecy): обмен ключей по алгоритму ECDHE(Elliptic Curve Diffie-Hellman Ephemeral), а шифрование по алгоритму AES-128 или AES-256.

TLS должен быть использован в одном из следующих режимов:

- `TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384`
- `TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256`
- `TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384`
- `TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA`
- `TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256`
- `TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA`
- `TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384`
- `TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256`
- `TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384`
- `TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256`
- `TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA`

##### Исключения ATS

Ограничения ATS могут быть отключены, с помощью конфигурации исключений в файле Info.plist, через модификацию ключа `NSAppTransportSecurity`. Эти исключения могут быть использованы, чтобы:

- разрешить незащищенные подключения (HTTP)
- понизить версию TLS
- отключить PFS
- разрешить подключения к локальным доменам.

Исключения ATS могут быть применены глобально или же только к конкретному домену. Приложение может глобально выключить ATS, но оставить его для некоторых доменов. Следующая выдержка из документации Apple показывает структуру словаря [NSAppTransportSecurity](https://developer.apple.com/library/content/documentation/General/Reference/InfoPlistKeyReference/Articles/CocoaKeys.html#//apple_ref/doc/plist/info/NSAppTransportSecurity "API Reference NSAppTransportSecurity").

```objc
NSAppTransportSecurity : Dictionary {
    NSAllowsArbitraryLoads : Boolean
    NSAllowsArbitraryLoadsForMedia : Boolean
    NSAllowsArbitraryLoadsInWebContent : Boolean
    NSAllowsLocalNetworking : Boolean
    NSExceptionDomains : Dictionary {
        <domain-name-string> : Dictionary {
            NSIncludesSubdomains : Boolean
            NSExceptionAllowsInsecureHTTPLoads : Boolean
            NSExceptionMinimumTLSVersion : String
            NSExceptionRequiresForwardSecrecy : Boolean   // Default value is YES
            NSRequiresCertificateTransparency : Boolean
        }
    }
}
```

Источник: [Apple Developer Documentation](https://developer.apple.com/library/content/documentation/General/Reference/InfoPlistKeyReference/Articles/CocoaKeys.html "Information Property List Key Reference: Cocoa Keys").

Следующая таблица резюмирует глобальные исключения в ATS. Для более подробной информации о этих исключениях обращайтесь к [таблице 2 в официальной документации Apple developer](https://developer.apple.com/library/content/documentation/General/Reference/InfoPlistKeyReference/Articles/CocoaKeys.html#//apple_ref/doc/uid/TP40009251-SW34 "App Transport Security dictionary primary keys").

|  Ключ | Описание |
| -----| ------------|
| `NSAllowsArbitraryLoads` | Выключает ограничения ATS глобально, исключаяя домены, указанные в `NSExceptionDomains` |
| `NSAllowsArbitraryLoadsInWebContent` | Выключает ограничения ATS для всех соединений, сделанных из WebViews |
| `NSAllowsLocalNetworking` | Разрешает соединение к неполным или локальным доменным именам |
| `NSAllowsArbitraryLoadsForMedia` | Выключает все ограничения ATS для медиа файлов, загруженных с использованием библиотеки AV Foundations |

Следующая таблица кратко излагает исключения ATS, применяемые к конкретным доменам. Для более подробной информации ссылайтесь на [таблицу 3 официальной документации Apple developer](https://developer.apple.com/library/content/documentation/General/Reference/InfoPlistKeyReference/Articles/CocoaKeys.html#//apple_ref/doc/uid/TP40009251-SW44 "App Transport Security dictionary primary keys").

|  Ключ | Описание |
| -----| ------------|
| `NSIncludesSubdomains` | Указывает применяются ли исключения ATS к поддоменам указанного домена |
| `NSExceptionAllowsInsecureHTTPLoads` | Разрашает HTTP соединения к указанному домену, но не распространяется на требования TLS |
| `NSExceptionMinimumTLSVersion` | Разрешает соединения к серверу, где версия TLS 1.2 или ниже |
| `NSExceptionRequiresForwardSecrecy` | Выключает PFS(perfect forward secrecy) |

Начиная с 1 января 2017 года, процесс ревью для публикации приложения в Apple App Store требует проверки было ли определено одно из исключений, указанных ниже, в ATS.

- `NSAllowsArbitraryLoads`
- `NSAllowsArbitraryLoadsForMedia`
- `NSAllowsArbitraryLoadsInWebContent`
- `NSExceptionAllowsInsecureHTTPLoads`
- `NSExceptionMinimumTLSVersion`

Однако, данная мера была отложена позже Apple, в заявлении: [“To give you additional time to prepare, this deadline has been extended and we will provide another update when a new deadline is confirmed”](https://developer.apple.com/news/?id=12212016b "Apple Developer Portal Announcement - Supporting App Transport Security").

#### Анализ конфигурации ATS

Если имеется возможность посмотреть исходный код, загляните в файл(находящийся в папке приложения) `Info.plist` и обратите внимание на исключения, которые настроил разработчик. Этот файл должен быть изучен, принимая во внимание контекст приложения.

Следующий отрывок - пример исключения, которое отключает ограничения ATS глобально.

```xml
	<key>NSAppTransportSecurity</key>
	<dict>
		<key>NSAllowsArbitraryLoads</key>
		<true/>
	</dict>
```

Если же исходный код недоступен, тогда файл `Info.plist` должен быть получен с взломанного устройства или же извлечен из IPA.

Так как IPA файлы - это ZIP архивы, они могут быть распакованы любой архивирующей утилитой:

```shell
$ unzip app-name.ipa
```

Файл `Info.plist` может быть найден в папке `Payload/BundleName.app/`. Это файл бинарного представления и его необходимо конвертировать в читаемый формат для дальнейшего анализа.

[`plutil`](https://www.theiphonewiki.com/wiki/Plutil "OS X Plutil") - это инструмент, предназначенный для этой цели. Он поставляется вместе с версией Mac OS 10.2 и выше.

Следующая команда показывает как конвертировать файл Info.plist в файл XML формата.

```shell
$ plutil -convert xml1 Info.plist
```
После того как файл приведен к читаемому формату, исключения могут быть проанализированы. Приложение могло включить исключения ATS, чтобы обеспечить свое нормальное функционирование. Например, приложение Firefox для iOS полностью выключило политику ATS. Данное исключение приемлимо, потому что в противном случае, приложение не сможет подключаться к любому сайту, который не поддерживает все требования ATS.

Подытоживая:

- ATS должен быть настроен, в соответствии с лучшими практиками, рекомендуемыми Apple и может быть отключен только из-за определенных обстоятельств.
- Если приложение подключается к известному количеству доменов, которые контролирует разработчик приложения, тогда настройте сервера, чтобы они соответствовали требованиям ATS и откажитесь от этих требований в приложении. В следующем примере, доменом `example.com` владеет разработчик приложения и ATS включено для этого домена.

    ```xml
    <key>NSAppTransportSecurity</key>
    <dict>
        <key>NSAllowsArbitraryLoads</key>
        <true/>
        <key>NSExceptionDomains</key>
        <dict>
            <key>example.com</key>
            <dict>
                <key>NSIncludesSubdomains</key>
                <true/>
                <key>NSExceptionMinimumTLSVersion</key>
                <string>TLSv1.2</string>
                <key>NSExceptionAllowsInsecureHTTPLoads</key>
                <false/>
                <key>NSExceptionRequiresForwardSecrecy</key>
                <true/>
            </dict>
        </dict>
    </dict>
    ```

- Если же происходит подключения к домену третьей стороны, то необходимо выявить какие настройки ATS не поддерживаются и могут ли они быть отключены.
- Если приложение открывает сайт третьей стороны в WebView, то начиная с iOS 10 `NSAllowsArbitraryLoadsInWebContent` может быть использована для отключения ограничений ATS для контента, загружаемого через WebViews.


### Проверка нестандартных хранилищ сертификатов и certificate pinning

#### Обзор

Certificate pinning - это процесс ассоциации мобильного приложения с конкретным сертификатом X509 сервера, вместо того, чтобы принимать любой сертификат, подписанный доверенным центром сертификации. Мобильное приложение, которое хранит сертификат сервера или же открытый ключ впоследствии будет устанавливать соединения только с известным сервером. По средствам удаления доверия внешним центрам сертификации поверхность атаки уменьшается(существует много известных случаев, когда ЦС были скомпрометированы или же втянуты в выдачу сертификатов мошенникам).

Сертификат может быть прикреплен во время разработки или же во время первого подключения к бекэнду. В этом случае, сертификат ассоциируется или же "пиннится" с хостом, во время первого подключения. Второй вариант чуть менее безопасный, так как злоумышленник может перехватить первое соединение и вставить туда свой собственный сертификат.

#### Статический анализ

Проверте что сертификат сервера прикреплен. Пиннинг может быть реализован разными способами:

1. Включение сертификата сервера в пакет приложения и верификация во время каждого соединения. Данный подход накладывает обязательство предусмотреть механизм обновления сертификата, когда сервер его обновляет.
2. Ограничение сущности, выдающей сертификаты, например, только один сертификат и встраивание открытого ключа промежуточного ЦС в приложение. Таким образом мы ограничиваем поверхность атак, а также получаем валидные сертификаты.
3. Владение и управление своим собственным PKI. В приложении будет хранится публичный ключ промежуточного ЦС. Данная мера предотвращает обновление сертификата каждый раз, когда он меняется на сервере из-за, например, истечения срока действия. Обратите внимание, что использование своего собственного ЦС принуждает вас использовать само-подписанные сертификаты.


Код ниже показывает как можно проверить сертификат, предоставленный сервером, на соответсвие с хранящимися в приложении. Метод реализует аутентификацию соединения и сообщает делегату, что соединение отправит запрос на проверку подлинности.

Делегат должен реализовать `connection:canAuthenticateAgainstProtectionSpace:` и `connection: forAuthenticationChallenge`. В `connection: forAuthenticationChallenge`, делегат должен вызвать `SecTrustEvaluate`, чтобы выполнить обычные проверки X509. Кусок кода ниже реализует проверку сертификата.

```objc
(void)connection:(NSURLConnection *)connection willSendRequestForAuthenticationChallenge:(NSURLAuthenticationChallenge *)challenge
{
  SecTrustRef serverTrust = challenge.protectionSpace.serverTrust;
  SecCertificateRef certificate = SecTrustGetCertificateAtIndex(serverTrust, 0);
  NSData *remoteCertificateData = CFBridgingRelease(SecCertificateCopyData(certificate));
  NSString *cerPath = [[NSBundle mainBundle] pathForResource:@"MyLocalCertificate" ofType:@"cer"];
  NSData *localCertData = [NSData dataWithContentsOfFile:cerPath];
  The control below can verify if the certificate received by the server is matching the one pinned in the client.
  if ([remoteCertificateData isEqualToData:localCertData]) {
  NSURLCredential *credential = [NSURLCredential credentialForTrust:serverTrust];
  [[challenge sender] useCredential:credential forAuthenticationChallenge:challenge];
}
else {
  [[challenge sender] cancelAuthenticationChallenge:challenge];
}
```

#### Динамический анализ

##### Валидация сертификата сервера

Наш подход к тестированию заключается в постепенном снижении безопасности согласования SSL handshake и проверке какие механизмы безопасности включены.

1. Установив Burp как proxy, убедитесь, что нет сертификатов, добавленных в доверенное хранилище (Settings -> General -> Profiles), а также что инструменты, такие как SSL Kill Switch выключены. Запустите свое приложение и посмотрите можете ли вы видеть траффик в Burp. Любые неудачи будут показаны во вкладке 'Alerts'. Если вы можете видеть траффик - это значит, что нет совсем никакой валидации сертификатов. Если же, вы не видите никакого траффика и у вас есть информация о провале SSL handshake, переходите к следующему шагу.
2. Теперь, установите сертификат Burp, как объяснено в [the portswigger user documentation](https://support.portswigger.net/customer/portal/articles/1841109-installing-burp-s-ca-certificate-in-an-ios-device "Installing Burp's CA Certificate in an iOS Device"). Если SSL handshake завершился успешно и вы можете видеть траффик в Burp, это значит, что сертификат был провалидирован во внутреннем доверительном хранилище, но pinning не был применен.
3. Если выполненные инструкции не привели к проксированию траффика через Burp, значит сертификат действительно pinned и все меры безопасности были соблюдены. Однако, вам все равно надо обойти SSL pinning, для того чтобы протестировать приложение. Пожалуйста, откройте главу "Базовое тестирование безопасности" для получения более полной информации.

##### Валидация клиентского сертификата

Некоторые приложения используют двухсторонний SSL handshake, означающий, что приложение проверяет сертификат сервера, а сервер проверяет сертификат приложения. Вы можете заметить это в Burp, во вкладке 'Alerts', информирующей, что у клиента не удалось установить соединение.

Есть пару вещей, на которые стоит обратить внимание:

1. Клиент содержит закрытый ключ, который будет использован в обмене.
2. Обычно, для расшифрования(использования) сертификата потребуется пароль.
3. Сертификат может хранится в бинарном формате, в папке с данными или же в Keychain.

Самый распространенный и неправильный способ осуществления двухстороннего SSL handshake - это хранение сертификата в пакете приложения и захардкодить пароли. Это очевидно не привносит много безопасности, потому что все клиенты будут использовать один и тот же сертификат.

Второй способ хранения сертификата(и возможно пароля)- это использование Keychain. До первого логина, приложению следует загрузить личный сертификат и безопасно его сохранить в Keychain.

Иногда у приложений есть один сертификат, захардкоденный, он используется для первого входа, после чего личный сертификат загружается. В этом случае, проверте, возможно ли использование общего(захардкоденного) сертификата для осуществления подключения к серверу.

После того как вы извлекли сертификат из приложения (например, используя cycript или же frida), добавте его в Burp, и вы сможете перехватывать траффик.

#### Ссылки

##### OWASP Mobile Top 10 2016

- M3 - Недостаточная защита транспортного протокола - https://owasp.org/www-project-mobile-top-10/2014-risks/m3-insufficient-transport-layer-protection

##### OWASP MASVS

- V5.1: "Данные шифруются в сети с использованием TLS. Безопасный канал используется последовательно во всем приложении."
- V5.2: "Настройки TLS соответствуют современным рекомендациям или максимально приближены к ним, если мобильная операционная система не поддерживает рекомендуемые стандарты."
- V5.3: "Приложение проверяет сертификат X.509 удаленного сервера, когда установлен защищенный канал. Принимаются только сертификаты, подписанные доверенным центром сертификации(CA)."
- V5.4: "Приложение использует свое собственное хранилище сертификатов или связывает сертификат конечной точки или открытый ключ и впоследствии не устанавливает соединения с конечными точками, которые предлагают другой сертификат или ключ, даже если они подписаны доверенным ЦС."

##### CWE

- CWE-319 - Передача чувствительной информации текстом(cleartext)
- CWE-326 - Недостаточная мощность шифрования
- CWE-295 - Неправильная валидация сертификатов
