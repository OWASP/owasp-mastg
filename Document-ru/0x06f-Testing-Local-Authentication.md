## Локальная аутентификация в iOS

Во время локальной аутентификации, приложение аутентифицирует пользователя, используя учетный данные, хранящиеся локально на устройстве. Проще говоря, пользователь "открывает" приложение или некоторый внутренний уровень его функциональности, предоставляя верный PIN, пароль или отпечаток пальца, верифицируемые по ссылке на локальные данные. В общем, это сделано, чтобы пользователь мог продолжить существующую сессию с удаленным сервером или же как упреждающая мера аутентификации, чтобы защитить некую критичную функциональность.


### Проверка локальной аутентификации

На iOS существуют разнообразные методы, которые позволяют интегрировать локальную аутентификацию в приложение. [Local Authentication framework](https://developer.apple.com/documentation/localauthentication)
предоставляет набор API для разработчиков, чтобы расширять возможности диалога аутентификации пользователя. В контексте подключения к удаленному сервису есть возможность(и это рекомендуется) использовать [Keychain]( https://developer.apple.com/library/content/documentation/Security/Conceptual/keychainServConcepts/01introduction/introduction.html) для реализации локальной аутентификации.

Аутентификация по отпечаткам пальцев на iOS известна как *Touch ID*. Сенсор отпечатков пальцев управляется
[SecureEnclave security coprocessor](http://mista.nu/research/sep-paper.pdf "Demystifying the Secure Enclave Processor by Tarjei Mandt, Mathew Solnik, and David Wang") и не предоставляет доступ к данным отпечатков пальцев ни каким другим частям системы.

У разработчиков есть два варианта интеграции аутентификации Touch ID:

- `LocalAuthentication.framework` - это API высокого уровня, которое может быть использовано для аутентификации пользователя с помощью Touch ID. Приложение не может получить доступ к какой-либо информации, связанной с вовлеченным отпечатком пальцев и только лишь уведомляет о успехе операции
- `Security.framework`- это API низкого уровня для доступа к [Keychain Services](https://developer.apple.com/documentation/security/keychain_services "Keychain Services"). Это безопасный вариант, если вашему приложению необходимо защитить какую-либо секретную информацию, используя биометрическую аутентификацию, так как управление доступом осуществляется на уровне системы, данную защиту не так-то просто обойти. `Security.framework` имеет API языка С, но также существуют некоторые [обертки в открытом доступе](https://www.raywenderlich.com/147308/secure-ios-user-data-keychain-touch-id "How To Secure iOS User Data: The Keychain and Touch ID"), делая доступ к Keychain таким же простым как и к NSUserDefaults. `Security.framework` лежит в основе `LocalAuthentication.framework`; рекомендация Apple, по умолчанию, использовать API более высокого уровня, если это возможно.

##### Библиотека Local Authentication

Библиотека Local Authentication предоставляет возможности для запроса код-пароля или же Touch ID у пользователя. Разработчики могут отображать и использовать аутентификационное диалоговое окно, воспользовавшись функцией `evaluatePolicy` класса `LAContext`.

Две доступные политики определяют приемлимые формы аутентификации:

- `deviceOwnerAuthentication`(Swift) или `LAPolicyDeviceOwnerAuthentication`(Objective-C): Когда возможно, пользователю предлагается выполнить аутентификацию Touch ID. Если данная функция не активирована, то вместо этого предлагают ввести код-пароль. Если же защита код-паролем не включена, проверка политики завершается неудачей.

- `deviceOwnerAuthenticationWithBiometrics` (Swift) or `LAPolicyDeviceOwnerAuthenticationWithBiometrics`(Objective-C): Данная аутентификация ограничена биометрией, где пользователя просят воспользоваться TouchID.

Функция `evaluatePolicy` возвращает булево значение, означающее успешно ли выполнилась аутентификация.

Сайт Apple Developer предлагает примеры кода и для [Swift](https://developer.apple.com/documentation/localauthentication) и для [Objective-C](https://developer.apple.com/documentation/localauthentication?language=objc). Типичная реализация на Swift выглядит следующим образом:

```swift
let context = LAContext()
var error: NSError?

guard context.canEvaluatePolicy(.deviceOwnerAuthentication, error: &error) else {
	// Could not evaluate policy; look at error and present an appropriate message to user
}

context.evaluatePolicy(.deviceOwnerAuthentication, localizedReason: "Please, pass authorization to enter this area") { success, evaluationError in
	guard success else {
		// User did not authenticate successfully, look at evaluationError and take appropriate action
	}

	// User authenticated successfully, take appropriate action
}
```
*Touch ID аутентификация в Swift, используя библиотеку Local Authentication (оффициальные пример кода от Apple).*

#####  Использование сервисов Keychain для локальной аутентификации

API Keychain для iOS могут(и должны) использоваться для реализации локальной аутентификации. Во время этого процесса, приложение хранит либо секретный токен аутентификации либо же другой кусок секретной информации, идентифицирующий пользователя в Keychain. Для того чтобы выполнить аутентификацию в удаленный сервис, пользователю необходимо разлочить Keychain, используя код-пароль или же отпечаток пальца, чтобы получить секретные данные.

Keychain позволяет сохранять объекты(записи) со специальным аттрибутом `SecAccessControl`, который позволяет получить доступ к объекту Keychain только после того как пользовать успешно пройдет атентификацию Touch ID(или же код-пароля, если такой откат разрешен параметром аттрубута).

В следующем примере мы сохраним строку "test_strong_password" в Keychain. Строка может быть доступна только с текущего устройства, когда код-пароль установлен(параметр `kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly`) и только после того как аутентификация Touch ID для вовлеченного в данный момент пальца будет успешна(параметр `.touchIDCurrentSet`):

**Swift**

```swift
// 1. create AccessControl object that will represent authentication settings

var error: Unmanaged<CFError>?

guard let accessControl = SecAccessControlCreateWithFlags(kCFAllocatorDefault,
	kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly,
	.touchIDCurrentSet,
	&error) else {
    // failed to create AccessControl object
}

// 2. define Keychain services query. Pay attention that kSecAttrAccessControl is mutually exclusive with kSecAttrAccessible attribute

var query: Dictionary<String, Any> = [:]

query[kSecClass as String] = kSecClassGenericPassword
query[kSecAttrLabel as String] = "com.me.myapp.password" as CFString
query[kSecAttrAccount as String] = "OWASP Account" as CFString
query[kSecValueData as String] = "test_strong_password".data(using: .utf8)! as CFData
query[kSecAttrAccessControl as String] = accessControl

// 3. save item

let status = SecItemAdd(query as CFDictionary, nil)

if status == noErr {
	// successfully saved
} else {
	// error while saving
}
```

**Objective-C**

```objc
// 1. create AccessControl object that will represent authentication settings
CFErrorRef *err = nil;

SecAccessControlRef sacRef = SecAccessControlCreateWithFlags(kCFAllocatorDefault,
	kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly,
	kSecAccessControlUserPresence,
	err);

// 2. define Keychain services query. Pay attention that kSecAttrAccessControl is mutually exclusive with kSecAttrAccessible attribute
NSDictionary *query = @{ (__bridge id)kSecClass: (__bridge id)kSecClassGenericPassword,
	(__bridge id)kSecAttrLabel: @"com.me.myapp.password",
	(__bridge id)kSecAttrAccount: @"OWASP Account",
	(__bridge id)kSecValueData: [@"test_strong_password" dataUsingEncoding:NSUTF8StringEncoding],
	(__bridge id)kSecAttrAccessControl: (__bridge_transfer id)sacRef };

// 3. save item
OSStatus status = SecItemAdd((__bridge CFDictionaryRef)query, nil);

if (status == noErr) {
	// successfully saved
} else {
	// error while saving
}

```

После этого мы можем запрашивать сохраненный объект из Keychain. Сервисы Keychain предоставят аутентификационное окно пользователю и возвратят данные или же nil, в зависимости от того был ли предоставлен правильный отпечаток пальца или нет.

**Swift**

```swift
// 1. define query
var query = [String: Any]()
query[kSecClass as String] = kSecClassGenericPassword
query[kSecReturnData as String] = kCFBooleanTrue
query[kSecAttrAccount as String] = "My Name" as CFString
query[kSecAttrLabel as String] = "com.me.myapp.password" as CFString
query[kSecUseOperationPrompt as String] = "Please, pass authorisation to enter this area" as CFString

// 2. get item
var queryResult: AnyObject?
let status = withUnsafeMutablePointer(to: &queryResult) {
    SecItemCopyMatching(query as CFDictionary, UnsafeMutablePointer($0))
}

if status == noErr {
    let password = String(data: queryResult as! Data, encoding: .utf8)!
    // successfully received password
} else {
    // authorization not passed
}
```

**Objective-C**

```objc
// 1. define query
NSDictionary *query = @{(__bridge id)kSecClass: (__bridge id)kSecClassGenericPassword,
    (__bridge id)kSecReturnData: @YES,
    (__bridge id)kSecAttrAccount: @"My Name1",
    (__bridge id)kSecAttrLabel: @"com.me.myapp.password",
    (__bridge id)kSecUseOperationPrompt: @"Please, pass authorisation to enter this area" };

// 2. get item
CFTypeRef queryResult = NULL;
OSStatus status = SecItemCopyMatching((__bridge CFDictionaryRef)query, &queryResult);

if (status == noErr){
    NSData *resultData = ( __bridge_transfer NSData *)queryResult;
    NSString *password = [[NSString alloc] initWithData:resultData encoding:NSUTF8StringEncoding];
    NSLog(@"%@", password);
} else {
    NSLog(@"Something went wrong");
}
```
Использование библиотек в приложении может быть легко определено с помощью анализа списка общих динамических библиотек приложения. Это может быть выполнено с помощью otool:

```shell
$ otool -L <AppName>.app/<AppName>
```

Если `LocalAuthentication.framework` используется в приложении, вывод будет содержать две следующие линии(запомните, что `LocalAuthentication.framework` использует `Security.framework` под капотом):

```
/System/Library/Frameworks/LocalAuthentication.framework/LocalAuthentication
/System/Library/Frameworks/Security.framework/Security
```

Если `Security.framework` использован, только вторая строка будет выведена.

#### Статический анализ

Очень важно запомнить, что библиотека Local Authentication - это событийная процедура, и как таковая не может предоставлять единственный метод аутентификации. Несмотря на то что такой уровень аутентификации эффективен на уровне интерфейса пользователя, он очень легко обходится через патч или же инструментирование.

- Убедитесь, что чувствительные процессы, такие как пере-аутентификация или же проведение платежной транзакции пользователем защищено с использованием методов Keychain.
- Убедитесь, что политика `kSecAccessControlUserPresence` и защита `kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly` установлены, когда метод `SecAccessControlCreateWithFlags` вызывается.

#### Динамический анализ

На взломанных устройствах, инструменты [Swizzler2](https://github.com/vtky/Swizzler2 "Swizzler2") и [Needle](https://github.com/mwrlabs/needle "Needle") могут быть использованы чтобы обойти LocalAuthentication. Оба инструмента используют Frida для инструментирования функции `evaluatePolicy` так, что она возвращает `True`, даже если аутентификация удалась. Выполните шаги ниже, чтобы активировать эту функцию в Swizzler2:

- Настройки->Swizzler
- Включите "Inject Swizzler into Apps"
- Включите "Log Everything to Syslog"
- Включите "Log Everything to File"
- Войдите в подменю "iOS Frameworks"
- Включите "LocalAuthentication"
- Войдите в подменю "Select Target Apps"
- Включите целевое приложение
- Перезагрузите приложение
- Когда появляется информация с просьбой ввести TouchID нажмите "cancel"
- Если приложение продолжает работу без запроса Touch ID, значит техника обхода удалась.

Если вы используете Neddle, запустите модуль ``hooking/frida/script_touch-id-bypass`` и следуйте подсказкам. Данное действие запустит приложение и инстурментирование функции `evaluatePolicy`. Когда всплывает окно с просьбой выполнить аутентификацию, используя Touch ID, нажмите кнопку отмена. Если приложение продолжит работать, значит вы успешно обошли Touch ID. Похожий модуль(hooking/cycript/cycript_touchid), который использует cycript вместо frida также доступен в Needle.

Альтернативно вы можете использовать [objection to bypass TouchID](https://github.com/sensepost/objection/wiki/Understanding-the-TouchID-Bypass "Understanding the TouchID Bypass")(данный метод также работает на невзломанных устройствах). Пропатчите приложение или используйте Cycript или же похожий инструмент, чтобы проинструментировать процесс.

Needle также может использоваться, чтобы обойти биометрическую аутентификацию на платформе iOS. Needle использует Frida, чтобы обойти формы логина, разработанные с использованием API `LocalAuthentication.framework`. Следующий модуль может быть использован для тестирования небезопасной биометрической аутентификации:

```
[needle][container] > use hooking/frida/script_touch-id-bypass
[needle][script_touch-id-bypass] > run
```

Если тестируемая реализация уязвима, модуль автоматически обойдет форму логина.

### Ссылки

#### OWASP Mobile Top 10 2016

- M4 - Небезопасная аутентификация - https://owasp.org/www-project-mobile-top-10/2016-risks/m4-insecure-authentication

#### OWASP MASVS

- V4.8: "Биометрическая аутентификация, если она есть, не связана с событиями (т.е. с использованием API, который просто возвращает «истина» или «ложь»). Вместо этого она основана на разблокировке keychain/keystore."

#### CWE

- CWE-287 - Improper Authentication
