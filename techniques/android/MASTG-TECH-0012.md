---
title: Bypassing Certificate Pinning
platform: android
---

Some applications will implement SSL Pinning, which prevents the application from accepting your intercepting certificate as a valid certificate. This means that you will not be able to monitor the traffic between the application and the server.

For most applications, certificate pinning can be bypassed within seconds, but only if the app uses the API functions that are covered by these tools. If the app is implementing SSL Pinning with a custom framework or library, the SSL Pinning must be manually patched and deactivated, which can be time-consuming.

This section describes various ways to bypass SSL Pinning and gives guidance about what you should do when the existing tools don't help.

## Bypassing Methods

There are several ways to bypass certificate pinning for a black box test, depending on the frameworks available on the device:

- Frida: Use @MASTG-TOOL-0140
- Objection: Use the `android sslpinning disable` command.
- Xposed: Install the [TrustMeAlready](https://github.com/ViRb3/TrustMeAlready "TrustMeAlready") or the @MASTG-TOOL-0025 module.

If you have a rooted device with frida-server installed, you can bypass SSL pinning by running the following @MASTG-TOOL-0038 command (see @MASTG-TECH-0004 if you're using a non-rooted device):

```bash
android sslpinning disable
```

Here's an example of the output:

<img src="Images/Chapters/0x05b/android_ssl_pinning_bypass.png" width="100%" />

See also [Objection's help on Disabling SSL Pinning for Android](https://github.com/sensepost/objection/blob/master/objection/console/helpfiles/android.sslpinning.disable.txt) for further information and inspect the [pinning.ts](https://github.com/sensepost/objection/blob/master/agent/src/android/pinning.ts "pinning.ts") file to understand how the bypass works.

Note that the frida-multiple-unpinning script from @MASTG-TOOL-0032 covers more scenarios than the Objection script.

## Bypass Custom Certificate Pinning Statically

Somewhere in the application, both the endpoint and the certificate (or its hash) must be defined. After decompiling the application, you can search for:

- Certificate hashes: `grep -ri "sha256\|sha1" ./smali`. Replace the identified hashes with the hash of your proxy's CA. Alternatively, if the hash is accompanied by a domain name, you can try modifying the domain name to a non-existing domain so that the original domain is not pinned. This works well on obfuscated OkHTTP implementations.
- Certificate files: `find ./assets -type f \( -iname \*.cer -o -iname \*.crt \)`. Replace these files with your proxy's certificates, making sure they are in the correct format.
- Truststore files: `find ./ -type f \( -iname \*.jks -o -iname \*.bks \)`. Add your proxy's certificates to the truststore and make sure they are in the correct format.

> Keep in mind that an app might contain files without extension. The most common file locations are `assets` and `res` directories, which should also be investigated.

As an example, let's say that you find an application which uses a BKS (BouncyCastle) truststore and it's stored in the file `res/raw/truststore.bks`. To bypass SSL Pinning you need to add your proxy's certificate to the truststore with the command line tool `keytool`. `Keytool` comes with the Java SDK and the following values are needed to execute the command:

- password - Password for the keystore. Look in the decompiled app code for the hardcoded password.
- providerpath - Location of the BouncyCastle Provider jar file. You can download it from [The Legion of the Bouncy Castle](https://www.bouncycastle.org/latest_releases.html "https://www.bouncycastle.org/latest_releases.html").
- proxy.cer - Your proxy's certificate.
- aliascert - Unique value which will be used as alias for your proxy's certificate.

To add your proxy's certificate use the following command:

```bash
keytool -importcert -v -trustcacerts -file proxy.cer -alias aliascert -keystore "res/raw/truststore.bks" -provider org.bouncycastle.jce.provider.BouncyCastleProvider -providerpath "providerpath/bcprov-jdk15on-164.jar" -storetype BKS -storepass password
```

To list certificates in the BKS truststore use the following command:

```bash
keytool -list -keystore "res/raw/truststore.bks" -provider org.bouncycastle.jce.provider.BouncyCastleProvider -providerpath "providerpath/bcprov-jdk15on-164.jar"  -storetype BKS -storepass password
```

After making these modifications, repackage the application using apktool and install it on your device.

If the application uses native libraries to implement network communication, further reverse engineering is needed. An example of such an approach can be found in the blog post [Identifying the SSL Pinning logic in smali code, patching it, and reassembling the APK](https://serializethoughts.wordpress.com/2016/08/18/bypassing-ssl-pinning-in-android-applications/ "Bypassing SSL Pinning in Android Applications")

## Bypass Custom Certificate Pinning Dynamically

Bypassing the pinning logic dynamically makes it more convenient as there is no need to bypass any integrity checks and it's much faster to perform trial & error attempts.

Finding the correct method to hook is typically the hardest part and can take quite some time depending on the level of obfuscation. As developers typically reuse existing libraries, it is a good approach to search for strings and license files that identify the used library. Once the library has been identified, examine the non-obfuscated source code to find methods which are suited for dynamic instrumentation.

As an example, let's say that you find an application which uses an obfuscated OkHTTP3 library. The [documentation](https://square.github.io/okhttp/3.x/okhttp/ "OkHTTP3 documentation") shows that the `CertificatePinner.Builder` class is responsible for adding pins for specific domains. If you can modify the arguments to the [Builder.add method](https://square.github.io/okhttp/3.x/okhttp/okhttp3/CertificatePinner.Builder.html#add-java.lang.String-java.lang.String...- "Builder.add method"), you can change the hashes to the correct hashes belonging to your certificate. Finding the correct method can be done in either two ways, as explained in [this blog post](https://blog.nviso.eu/2019/04/02/circumventing-ssl-pinning-in-obfuscated-apps-with-okhttp/) by Jeroen Beckers:

- Search for hashes and domain names as explained in the previous section. The actual pinning method will typically be used or defined in close proximity to these strings
- Search for the method signature in the SMALI code

For the Builder.add method, you can find the possible methods by running the following grep command: `grep -ri java/lang/String;\[Ljava/lang/String;)L ./`

This command will search for all methods that take a string and a variable list of strings as arguments, and return a complex object. Depending on the size of the application, this may have one or multiple matches in the code.

Hook each method with Frida and print the arguments. One of them will print out a domain name and a certificate hash, after which you can modify the arguments to circumvent the implemented pinning.
