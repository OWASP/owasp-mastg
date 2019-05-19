## Криптографические API в iOS

В главе "Тестирование криптографии в мобильных приложениях" мы предоставили лучшие практики криптографии и описали типичные уязвимости, которые могут возникнуть в тех случаях, когда криптография была использована неправильно в мобильных приложениях. В этой главе мы детальнее остановимся на криптографических API в iOS. Мы покажем как можно распознать использование этих API в исходном коде, а также как интерпретировать настройку. Во время ревью кода, обязательно сравните использование криптографических параметров с лучшими практиками, прикрепленными в этом руководстве.


### Криптографические библиотеки в iOS

Apple предоставляет библиотеки с наиболее часто используемыми алгоритмами шифрования. Отличные источник информации- [Apple's Cryptographic Services Guide](https://developer.apple.com/library/content/documentation/Security/Conceptual/cryptoservices/GeneralPurposeCrypto/GeneralPurposeCrypto.html "Apple Cryptographic Services Guide"). В нем содержится расширенная документации на тему использования стандартных библиотек для инициализации и использования криптографических примитивов, что также является очень полезными знаниями во время ревью кода.

Код iOS обычно ссылается на предопределенные константы, объявленные в `CommonCryptor.h` (например, `kCCAlgorithmDES`). Вы можете воспользоваться поиском, чтобы найти использование таких констант в исходном коде. Обратите внимание на то, что константы в iOS численные, поэтому убедитесь, что константы передаются в `CCCrypt` для выполнения алгоритма, который, как мы знаем, является безопасным и не устаревшим.  

Если приложение использует стандартные реализации криптографии, предоставленные Apple, самый простой путь проверки - это посмотреть вызовы функций в `CommonCryptor`, такие как: `CCCrypt`, `CCCryptorCreate`, и т.д. [Исходный код](https://opensource.apple.com/source/CommonCrypto/CommonCrypto-36064/CommonCrypto/CommonCryptor.h "CommonCryptor.h") содержит сигнатуры всех функций. Например, `CCCryptorCreate` имеет следующую сигнатуру:

```c
CCCryptorStatus CCCryptorCreate(
	CCOperation op,             /* kCCEncrypt, etc. */
	CCAlgorithm alg,            /* kCCAlgorithmDES, etc. */
	CCOptions options,          /* kCCOptionPKCS7Padding, etc. */
	const void *key,            /* raw key material */
	size_t keyLength,
	const void *iv,             /* optional initialization vector */
	CCCryptorRef *cryptorRef);  /* RETURNED */
```

После этого вы можете посмотреть все параметры из `enum`, чтобы понять какой алгоритм был использован, какой отступ и из чего составлялись ключи. Уделите особое внимание из чего генерировался ключ, из пароля(что плохо) или же из Key Derivation Function (например, PBKDF2). Очевидно, что существуют другие нестандартные библиотеки, которые можно использовать(например, `openssl`), так что обратите внимание и на них.

Код iOS обычно ссылается на предопределенные константы, объявленные в `CommonCryptor.h` (например, `kCCAlgorithmDES`). Вы можете воспользоваться поиском, чтобы найти использование таких констант в исходном коде. Обратите внимание на то, что константы в iOS численные, поэтому убедитесь, что константы передаются в `CCCrypt` для исполнения алгоритма, который, как мы знаем, является безопасным и не устаревшим. Любое использование криптографии в приложении iOS должно следовать лучшим практикам, описанным в главе [Cryptography in Mobile Apps](0x04g-Testing-Cryptography.md).

### Генерация случайных чисел в iOS

Apple предоставляет разработчикам [Randomization Services](https://developer.apple.com/reference/security/randomization_services "Randomization Services") - API, которое генерирует криптографически безопасные случайные числа.

API сервисов рандомизации Apple использует функцию `SecRandomCopyBytes`, чтобы осуществлять генерацию. Это функция - обертка над `/dev/random` файлом, который предоставляет криптографически безопасные псевдорандомные числа от 0 до 255 и осуществляет конкатенацию.

Проверьте, что все случайные числа сгенерированы с использование этого API - нет ни одной причины почему разработчики использовали бы другой метод.

В Swift, [`SecRandomCopyBytes` API](https://developer.apple.com/reference/security/1399291-secrandomcopybytes "SecRandomCopyBytes (Swift)") опеределено следующим образом:

```
func SecRandomCopyBytes(_ rnd: SecRandomRef?,
                      _ count: Int,
                      _ bytes: UnsafeMutablePointer<UInt8>) -> Int32
```

[Objective-C версия](https://developer.apple.com/reference/security/1399291-secrandomcopybytes?language=objc "SecRandomCopyBytes (Objective-C)") выглядит так:

```
int SecRandomCopyBytes(SecRandomRef rnd, size_t count, uint8_t *bytes);
```

Использование:

```
int result = SecRandomCopyBytes(kSecRandomDefault, 16, randomBytes);
```

### Ссылки

#### OWASP Mobile Top 10 2016
- M5 - Недостаточная криптография - https://www.owasp.org/index.php/Mobile_Top_10_2016-M5-Insufficient_Cryptography

#### OWASP MASVS
- V3.3: "Приложение использует криптографические примитивы, которые подходят для конкретного прецедента, с параметрами, которые соответствуют лучшим практикам отрасли."
- V3.4: "Приложение не использует криптографические протоколы или алгоритмы, которые считаются в сообществе устаревшими, с точки зрения безопасности."
- V3.6: "Все случайные значения генерируются с использованием достаточно безопасного генератора случайных чисел."

#### CWE
- CWE-337 - Predictable Seed in PRNG
- CWE-338 - Use of Cryptographically Weak Pseudo-Random Number Generator (PRNG)
