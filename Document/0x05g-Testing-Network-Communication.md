## Android Network APIs

### Testing Endpoint Identify Verification (MSTG-NETWORK-3)

Using TLS to transport sensitive information over the network is essential for security. However, encrypting communication between a mobile application and its backend API is not trivial. Developers often decide on simpler but less secure solutions (e.g., those that accept any certificate) to facilitate the development process, and sometimes these weak solutions [make it into the production version](https://www.owasp.org/images/7/77/Hunting_Down_Broken_SSL_in_Android_Apps_-_Sascha_Fahl%2BMarian_Harbach%2BMathew_Smith.pdf "Hunting Down Broken SSL in Android Apps"), potentially exposing users to [man-in-the-middle attacks](https://cwe.mitre.org/data/definitions/295.html "CWE-295: Improper Certificate Validation").

Two key issues should be addressed:

- Verify that a certificate comes from a trusted source, i.e. a trusted CA (Certificate Authority).
- Determine whether the endpoint server presents the right certificate.

Make sure that the hostname and the certificate itself are verified correctly. Examples and common pitfalls are available in the [official Android documentation](https://developer.android.com/training/articles/security-ssl.html "Android Documentation - SSL"). Search the code for examples of `TrustManager` and `HostnameVerifier` usage. In the sections below, you can find examples of the kind of insecure usage that you should look for.

> Note that from Android 8.0 (API level 26) onward, there is no support for SSLv3 and `HttpsURLConnection` will no longer perform a fallback to an insecure TLS/SSL protocol.

#### Static Analysis

##### Verifying the Server Certificate

`TrustManager` is a means of verifying conditions necessary for establishing a trusted connection in Android. The following conditions should be checked at this point:

- Has the certificate been signed by a trusted CA?
- Has the certificate expired?
- Is the certificate self-signed?

The following code snippet is sometimes used during development and will accept any certificate, overwriting the functions `checkClientTrusted`, `checkServerTrusted`, and `getAcceptedIssuers`. Such implementations should be avoided, and, if they are necessary, they should be clearly separated from production builds to avoid built-in security flaws.

```Java
TrustManager[] trustAllCerts = new TrustManager[] {
    new X509TrustManager() {
        @Override
        public X509Certificate[] getAcceptedIssuers() {
            return new java.security.cert.X509Certificate[] {};
        }

        @Override
        public void checkClientTrusted(X509Certificate[] chain, String authType)
            throws CertificateException {
        }

        @Override
        public void checkServerTrusted(X509Certificate[] chain, String authType)
            throws CertificateException {
        }
    }
 };

// SSLContext context
context.init(null, trustAllCerts, new SecureRandom());
```

##### WebView Server Certificate Verification

Sometimes applications use a WebView to render the website associated with the application. This is true of HTML/JavaScript-based frameworks such as Apache Cordova, which uses an internal WebView for application interaction. When a WebView is used, the mobile browser performs the server certificate validation. Ignoring any TLS error that occurs when the WebView tries to connect to the remote website is a bad practice.

The following code will ignore TLS issues, exactly like the WebViewClient custom implementation provided to the WebView:

```java
WebView myWebView = (WebView) findViewById(R.id.webview);
myWebView.setWebViewClient(new WebViewClient(){
    @Override
    public void onReceivedSslError(WebView view, SslErrorHandler handler, SslError error) {
        //Ignore TLS certificate errors and instruct the WebViewClient to load the website
        handler.proceed();
    }
});
```

##### Apache Cordova Certificate Verification

Implementation of the Apache Cordova framework's internal WebView usage will ignore [TLS errors](https://github.com/apache/cordova-android/blob/master/framework/src/org/apache/cordova/engine/SystemWebViewClient.java "TLS errors ignoring by Apache Cordova in WebView") in the method `onReceivedSslError` if the flag `android:debuggable` is enabled in the application manifest. Therefore, make sure that the app is not debuggable. See the test case "Testing If the App is Debuggable".

##### Hostname Verification

Another security flaw in client-side TLS implementations is the lack of hostname verification. Development environments usually use internal addresses instead of valid domain names, so developers often disable hostname verification (or force an application to allow any hostname) and simply forget to change it when their application goes to production. The following code disables hostname verification:

```java
final static HostnameVerifier NO_VERIFY = new HostnameVerifier() {
    public boolean verify(String hostname, SSLSession session) {
        return true;
    }
};
```

With a built-in `HostnameVerifier`, accepting any hostname is possible:

```Java
HostnameVerifier NO_VERIFY = org.apache.http.conn.ssl.SSLSocketFactory
                             .ALLOW_ALL_HOSTNAME_VERIFIER;
```

Make sure that your application verifies a hostname before setting a trusted connection.

#### Dynamic Analysis

Dynamic analysis requires an interception proxy. To test improper certificate verification, check the following controls:

- Self-signed certificate

In Burp, go to the **Proxy** tab, select the **Options** tab, then go to the **Proxy Listeners** section, highlight your listener, and click **Edit**. Then go to the **Certificate** tab, check **Use a self-signed certificate**, and click **Ok**. Now, run your application. If you're able to see HTTPS traffic, your application is accepting self-signed certificates.

- Accepting certificates with an untrusted CA

In Burp, go to the **Proxy** tab, select the **Options** tab, then go to the **Proxy Listeners** section, highlight your listener, and click **Edit**. Then go to the **Certificate** tab, check **Generate a CA-signed certificate with a specific hostname**, and type in the backend server's hostname. Now, run your application. If you're able to see HTTPS traffic, your application is accepting certificates with an untrusted CA.

- Accepting incorrect hostnames

In Burp,go to the **Proxy** tab, select the **Options** tab, then go to the **Proxy Listeners** section, highlight your listener, and click **Edit**. Then go to the **Certificate** tab, check **Generate a CA-signed certificate with a specific hostname**, and type in an invalid hostname, e.g., example.org. Now, run your application. If you're able to see HTTPS traffic, your application is accepting all hostnames.

If you're interested in further MITM analysis or you have problems with the configuration of your interception proxy, consider using [Tapioca](https://insights.sei.cmu.edu/cert/2014/08/-announcing-cert-tapioca-for-mitm-analysis.html "Announcing CERT Tapioca for MITM Analysis"). It's a CERT pre-configured [VM appliance](http://www.cert.org/download/mitm/CERT_Tapioca.ova "CERT Tapioca Virtual Machine Download") for MITM software analysis. All you have to do is [deploy a tested application on an emulator and start capturing traffic](https://insights.sei.cmu.edu/cert/2014/09/-finding-android-ssl-vulnerabilities-with-cert-tapioca.html "Finding Android SSL vulnerabilities with CERT Tapioca").

### Testing Custom Certificate Stores and Certificate Pinning (MSTG-NETWORK-4)

#### Overview

Certificate pinning is the process of associating the backend server with a particular X.509 certificate or public key instead of accepting any certificate signed by a trusted certificate authority. After storing ("pinning") the server certificate or public key, the mobile app will subsequently connect to the known server only. Withdrawing trust from external certificate authorities reduces the attack surface (after all, there are many cases of certificate authorities that have been compromised or tricked into issuing certificates to impostors).

The certificate can be pinned and hardcoded into the app or retrieved at the time the app first connects to the backend. In the latter case, the certificate is associated with ("pinned" to) the host when the host is seen for the first time. This alternative is less secure because attackers intercepting the initial connection can inject their own certificates.

##### When the Pin Fails

Note that there are various options when dealing with a failing pin:

- Inform the user about not being able to connect to the backend and stop all operations. The app can check whether there is an update and inform the user about updating to the latest version of the app if available. The app allows no longer for any form of interaction with the user until it is updated or the pin works again.
- Do a call to a crash-reporting service including information about the failed pin. The responsible developers should get notified about a potential security misconfiguration.
- The app calls the backend using a TLS enabled call with no pinning to inform the backend of a pinning failure. The call can either differ in user-agent, JWT token-contents, or have other headers with a flag enabled as an indication of pinning failure.
- After calling the backend or crash-reporting service to notify about the failing pinning, the app can still offer limited functionality that shouldn't involve sensitive functions or processing of sensitive data. The communication would happen without SSL Pinning and just validate the X.509 certificate accordingly.

Which option(s) you choose depends on how important availability is compared to the complexity of maintaining the application.

When a large amount of pinfailures are reported to the backend or crash-reporting service, the developer should understand that there is probably a misconfiguration. There is a large chance that the key materials used at the TLS terminating endpoint (e.g. server/loadbalancer) is different than what the app is expecting. In that case, an update of either that key material or an update of the app should be pushed through.

When only very few pin failures are reported, then the network should be ok, and so should be the configuration of the TLS terminating endpoint. Instead, it might well be that there is a man-in-the-middle attack ongoing at the app instance of which the pin is failing.

#### Static Analysis

##### Network Security Configuration

To customize their network security settings in a safe, declarative configuration file without modifying app code, applications can use the [Network Security Configuration](https://developer.android.com/training/articles/security-config.html "Network Security Configuration documentation") that Android provides for versions 7.0 and above.

The Network Security Configuration can also be used to pin [declarative certificates](https://developer.android.com/training/articles/security-config.html#CertificatePinning "Certificate Pinning using Network Security Configuration") to specific domains. If an application uses this feature, two things should be checked to identify the defined configuration:

First, find the Network Security Configuration file in the Android application manifest via the `android:networkSecurityConfig` attribute on the application tag:

  ```xml
  <?xml version="1.0" encoding="utf-8"?>
  <manifest xmlns:android="http://schemas.android.com/apk/res/android" package="owasp.com.app">
      <application android:networkSecurityConfig="@xml/network_security_config">
          ...
      </application>
  </manifest>
  ```

Open the identified file. In this case, the file can be found at "res/xml/network_security_config.xml":

  ```xml
  <?xml version="1.0" encoding="utf-8"?>
  <network-security-config>
      <domain-config>
          <!-- Use certificate pinning for OWASP website access including sub domains -->
          <domain includeSubdomains="true">owasp.org</domain>
          <pin-set expiration="2018/8/10">
              <!-- Hash of the public key (SubjectPublicKeyInfo of the X.509 certificate) of
              the Intermediate CA of the OWASP website server certificate -->
              <pin digest="SHA-256">YLh1dUR9y6Kja30RrAn7JKnbQG/uEtLMkBgFF2Fuihg=</pin>
              <!-- Hash of the public key (SubjectPublicKeyInfo of the X.509 certificate) of
              the Root CA of the OWASP website server certificate -->
              <pin digest="SHA-256">Vjs8r4z+80wjNcr1YKepWQboSIRi63WsWXhIMN+eWys=</pin>
          </pin-set>
      </domain-config>
  </network-security-config>
  ```

> The pin-set contains a set of public key pins. Each set can define an expiration date. When the expiration date is reached, the network communication will continue to work, but the Certificate Pinning will be disabled for the affected domains.

If a configuration exists, the following event may be visible in the log:

```shell
D/NetworkSecurityConfig: Using Network Security Config from resource network_security_config
```

If a certificate pinning validation check has failed, the following event will be logged:

```shell
I/X509Util: Failed to validate the certificate chain, error: Pin verification failed
```

Using a decompiler (e.g. jadx or apktool) we will be able to confirm if the `<pin>` entry is present in the network_security_config.xml file located in the /res/xml/ folder.

##### TrustManager

Implementing certificate pinning involves three main steps:

- Obtain the certificate of the desired host(s).
- Make sure the certificate is in .bks format.
- Pin the certificate to an instance of the default Apache Httpclient.

To analyze the correct implementation of certificate pinning, the HTTP client should load the KeyStore:

```java
InputStream in = resources.openRawResource(certificateRawResource);
keyStore = KeyStore.getInstance("BKS");
keyStore.load(resourceStream, password);
```

Once the KeyStore has been loaded, we can use the TrustManager that trusts the CAs in our KeyStore:

```java
String tmfAlgorithm = TrustManagerFactory.getDefaultAlgorithm();
TrustManagerFactory tmf = TrustManagerFactory.getInstance(tmfAlgorithm);
tmf.init(keyStore);
// Create an SSLContext that uses the TrustManager
// SSLContext context = SSLContext.getInstance("TLS");
sslContext.init(null, tmf.getTrustManagers(), null);
```

The app's implementation may be different, pinning against the certificate's public key only, the whole certificate, or a whole certificate chain.

##### Network Libraries and WebViews

Applications that use third-party networking libraries may utilize the libraries' certificate pinning functionality. For example, [okhttp](https://github.com/square/okhttp/wiki/HTTPS "okhttp library") can be set up with the `CertificatePinner` as follows:

```java
OkHttpClient client = new OkHttpClient.Builder()
        .certificatePinner(new CertificatePinner.Builder()
            .add("example.com", "sha256/UwQAapahrjCOjYI3oLUx5AQxPBR02Jz6/E2pt0IeLXA=")
            .build())
        .build();
```

Applications that use a WebView component may utilize the WebViewClient's event handler for some kind of "certificate pinning" of each request before the target resource is loaded. The following code shows an example verification:

```java
WebView myWebView = (WebView) findViewById(R.id.webview);
myWebView.setWebViewClient(new WebViewClient(){
    private String expectedIssuerDN = "CN=Let's Encrypt Authority X3,O=Let's Encrypt,C=US;";

    @Override
    public void onLoadResource(WebView view, String url)  {
        //From Android API documentation about "WebView.getCertificate()":
        //Gets the SSL certificate for the main top-level page
        //or null if there is no certificate (the site is not secure).
        //
        //Available information on SslCertificate class are "Issuer DN", "Subject DN" and validity date helpers
        SslCertificate serverCert = view.getCertificate();
        if(serverCert != null){
            //apply either certificate or public key pinning comparison here
                //Throw exception to cancel resource loading...
            }
        }
    }
});
```

Alternatively, it is better to use an OkHttpClient with configured pins and let it act as a proxy overriding `shouldInterceptRequest` of the `WebViewClient`.

##### Xamarin Applications

Applications developed in Xamarin will typically use ServicePointManager to implement pinning.

Normally a function is created to check the certificate(s) and return the boolean value to the method ServerCertificateValidationCallback:

```c#
[Activity(Label = "XamarinPinning", MainLauncher = true)]
    public class MainActivity : Activity
    {
        // SupportedPublicKey - Hexadecimal value of the public key.
        // Use GetPublicKeyString() method to determine the public key of the certificate we want to pin. Uncomment the debug code in the ValidateServerCertificate function a first time to determine the value to pin.
        private const string SupportedPublicKey = "3082010A02820101009CD30CF05AE52E47B7725D3783B3686330EAD735261925E1BDBE35F170922FB7B84B4105ABA99E350858ECB12AC468870BA3E375E4E6F3A76271BA7981601FD7919A9FF3D0786771C8690E9591CFFEE699E9603C48CC7ECA4D7712249D471B5AEBB9EC1E37001C9CAC7BA705EACE4AEBBD41E53698B9CBFD6D3C9668DF232A42900C867467C87FA59AB8526114133F65E98287CBDBFA0E56F68689F3853F9786AFB0DC1AEF6B0D95167DC42BA065B299043675806BAC4AF31B9049782FA2964F2A20252904C674C0D031CD8F31389516BAA833B843F1B11FC3307FA27931133D2D36F8E3FCF2336AB93931C5AFC48D0D1D641633AAFA8429B6D40BC0D87DC3930203010001";

        private static bool ValidateServerCertificate(
                object sender,
                X509Certificate certificate,
                X509Chain chain,
                SslPolicyErrors sslPolicyErrors
            )
        {
            //Log.Debug("Xamarin Pinning",chain.ChainElements[X].Certificate.GetPublicKeyString());
            //return true;
            return SupportedPublicKey == chain.ChainElements[1].Certificate.GetPublicKeyString();
        }

        protected override void OnCreate(Bundle savedInstanceState)
        {
            System.Net.ServicePointManager.ServerCertificateValidationCallback += ValidateServerCertificate;
            base.OnCreate(savedInstanceState);
            SetContentView(Resource.Layout.Main);
            TesteAsync("https://security.claudio.pt");

        }
```

In this particular example we are pinning the intermediate CA of the certificate chain. The output of the HTTP response will be available in the system logs.

Sample Xamarin app with the previous example can be obtained on the [MSTG repository](https://github.com/OWASP/owasp-mstg/raw/master/Samples/Android/02_CertificatePinning/certificatePinningXamarin.apk "Xamarin app with certificate pinning")

After decompressing the APK file, use a .NET decompiler like dotPeak, ILSpy or dnSpy to decompile the app dlls stored inside the 'Assemblies' folder and confirm the usage of the ServicePointManager.

##### Cordova Applications

Hybrid applications based on Cordova do not support Certificate Pinning natively, so plugins are used to achieve this. The most common one is PhoneGap SSL Certificate Checker. The `check` method is used to confirm the fingerprint and callbacks will determine the next steps.

```javascript
  // Endpoint to verify against certificate pinning.
  var server = "https://www.owasp.org";
  // SHA256 Fingerprint (Can be obtained via "openssl s_client -connect hostname:443 | openssl x509 -noout -fingerprint -sha256"
  var fingerprint = "D8 EF 3C DF 7E F6 44 BA 04 EC D5 97 14 BB 00 4A 7A F5 26 63 53 87 4E 76 67 77 F0 F4 CC ED 67 B9";

  window.plugins.sslCertificateChecker.check(
          successCallback,
          errorCallback,
          server,
          fingerprint);

   function successCallback(message) {
     alert(message);
     // Message is always: CONNECTION_SECURE.
     // Now do something with the trusted server.
   }

   function errorCallback(message) {
     alert(message);
     if (message === "CONNECTION_NOT_SECURE") {
       // There is likely a man in the middle attack going on, be careful!
     } else if (message.indexOf("CONNECTION_FAILED") >- 1) {
       // There was no connection (yet). Internet may be down. Try again (a few times) after a little timeout.
     }
   }
```

After decompressing the APK file, Cordova/Phonegap files will be located in the /assets/www folder. The 'plugins' folder will give you the visibility of the plugins used. We will need to search for this methods in the JavaScript code of the application to confirm its usage.

#### Dynamic Analysis

Dynamic analysis can be performed by launching a MITM attack with your preferred interception proxy. This will allow you to monitor the traffic between the client (the mobile application) and the backend server. If the proxy is unable to intercept the HTTP requests and responses, the SSL pinning has been implemented correctly.

##### Bypassing Certificate Pinning

There are several ways to bypass certificate pinning for a black box test, depending on the frameworks available on the device:

- Frida: Use the [Universal Android SSL Pinning Bypass with Frida](https://codeshare.frida.re/@pcipolloni/universal-android-ssl-pinning-bypass-with-frida/ "Universal Android SSL Pinning Bypass with Frida") script.
- Objection: Use the `android sslpinning disable` command.
- Xposed: Install the [TrustMeAlready](https://github.com/ViRb3/TrustMeAlready "TrustMeAlready") or [SSLUnpinning](https://github.com/ac-pm/SSLUnpinning_Xposed "SSLUnpinning") module.
- Cydia Substrate: Install the [Android-SSL-TrustKiller](https://github.com/iSECPartners/Android-SSL-TrustKiller "Android-SSL-TrustKiller") package.

For most applications, certificate pinning can be bypassed within seconds, but only if the app uses the API functions that are covered by these tools. If the app is implementing SSL Pinning with a custom framework or library, the SSL Pinning must be manually patched and deactivated, which can be time-consuming.

###### Bypass Custom Certificate Pinning Statically

Somewhere in the application, both the endpoint and the certificate (or its hash) must be defined. After decompiling the application, you can search for:

- Certificate hashes: `grep -ri "sha256\|sha1" ./smali`. Replace the identified hashes with the hash of your proxy's CA. Alternatively, if the hash is accompanied by a domain name, you can try modifying the domain name to a non-existing domain so that the original domain is not pinned. This works well on obfuscated OkHTTP implementations.
- Certificate files: `find ./assets -type f \( -iname \*.cer -o -iname \*.crt \)`. Replace these files with your proxy's certificates, making sure they are in the correct format.
- Truststore files: `find ./ -type f \( -iname \*.jks -o -iname \*.bks \)`. Add your proxy's certificates to trustore, making sure they are in the correct format.

> Keep in mind that an app might contain files without extension. The most common file locations are `assets` and `res` directories, which should also be investigated.

As an example, let's say that you find an application which uses a BKS (BouncyCastle) truststore and it's stored in the file `res/raw/truststore.bks`. To bypass SSL Pinning you need to add your proxy's certificate to the truststore with the command line tool `keytool`. `Keytool` comes with the Java SDK and the following values are needed to execute the command:
- password - Password for the keystore. Look in the decompiled app code for the hardcoded password.
- providerpath - Location of the BouncyCastle Provider jar file. You can download it from [The Legion of the Bouncy Castle](https://www.bouncycastle.org/latest_releases.html "https://www.bouncycastle.org/latest_releases.html").
- proxy.cer - Your proxy's certificate.
- aliascert - Unique value which will be used as alias for your proxy's certificate.

To add your proxy's certificate use the following command:

```shell
$ keytool -importcert -v -trustcacerts -file proxy.cer -alias aliascert -keystore "res/raw/truststore.bks" -provider org.bouncycastle.jce.provider.BouncyCastleProvider -providerpath "providerpath/bcprov-jdk15on-164.jar" -storetype BKS -storepass password
```

To list certificates in the BKS truststore use the following command:

```shell
$ keytool -list -keystore "res/raw/truststore.bks" -provider org.bouncycastle.jce.provider.BouncyCastleProvider -providerpath "providerpath/bcprov-jdk15on-164.jar"  -storetype BKS -storepass password
```

After making these modifications, repackage the application using apktool and install it on your device.

If the application uses native libraries to implement network communication, further reverse engineering is needed. An example of such an approach can be found in the blog post [Identifying the SSL Pinning logic in smali code, patching it, and reassembling the APK](https://serializethoughts.wordpress.com/2016/08/18/bypassing-ssl-pinning-in-android-applications/ "Bypassing SSL Pinning in Android Applications")

###### Bypass Custom Certificate Pinning Dynamically

Bypassing the pinning logic dynamically makes it more convenient as there is no need to bypass any integrity checks and it's much faster to perform trial & error attempts.

Finding the correct method to hook is typically the hardest part and can take quite some time depending on the level of obfuscation. As developers typically reuse existing libraries, it is a good approach to search for strings and license files that identify the used library. Once the library has been identified, examine the non-obfuscated source code to find methods which are suited for dynamic instrumentation.

As an example, let's say that you find an application which uses an obfuscated OkHTTP3 library. The [documentation](https://square.github.io/okhttp/3.x/okhttp/ "OkHTTP3 documentation") shows that the CertificatePinner.Builder class is responsible for adding pins for specific domains. If you can modify the arguments to the [Builder.add method](https://square.github.io/okhttp/3.x/okhttp/okhttp3/CertificatePinner.Builder.html#add-java.lang.String-java.lang.String...- "Builder.add method"), you can change the hashes to the correct hashes belonging to your certificate. Finding the correct method can be done in either two ways:

- Search for hashes and domain names as explained in the previous section. The actual pinning method will typically be used or defined in close proximity to these strings
- Search for the method signature in the SMALI code

For the Builder.add method, you can find the possible methods by running the following grep command: `grep -ri java/lang/String;\[Ljava/lang/String;)L ./`

This command will search for all methods that take a string and a variable list of strings as arguments, and return a complex object. Depending on the size of the application, this may have one or multiple matches in the code.

Hook each method with Frida and print the arguments. One of them will print out a domain name and a certificate hash, after which you can modify the arguments to circumvent the implemented pinning.

### Testing the Network Security Configuration Settings (MSTG-NETWORK-4)

#### Overview

Network Security Configuration was introduced on Android 7.0 (API level 24) and lets apps customize their network security settings such as custom trust anchors and certificate pinning.

##### Trust Anchors

When running on Android 7.0 (API level 24) or higher, apps targeting those API levels will use a default Network Security Configuration that doesn't trust any user supplied CAs, reducing the possibility of MITM attacks by luring users to install malicious CAs.

This protection can be bypassed by using a custom Network Security Configuration with a custom trust anchor indicating that the app will trust user supplied CAs.

#### Static Analysis

Use a decompiler (e.g. jadx or apktool) to confirm the target SDK version. After decoding the the app you can look for the presence of `targetSDK` present in the file apktool.yml that was created in the output folder.

The Network Security Configuration should be analyzed to determine what settings are configured. The file is located inside the APK in the /res/xml/ folder with the name network_security_config.xml.

If there are custom `<trust-anchors>` present in a `<base-config>` or `<domain-config>`, that define a `<certificates src="user">` the application will trust user supplied CAs for those particular domains or for all domains. Example:

```xml
<?xml version="1.0" encoding="utf-8"?>
<network-security-config>
    <base-config>
        <trust-anchors>
            <certificates src="system"/>
            <certificates src="user"/>
        </trust-anchors>
    </base-config>
    <domain-config>
        <domain includeSubdomains="false">owasp.org</domain>
        <trust-anchors>
            <certificates src="system"/>
            <certificates src="user"/>
        </trust-anchors>
        <pin-set expiration="2018/8/10">
            <!-- Hash of the public key (SubjectPublicKeyInfo of the X.509 certificate) of
            the Intermediate CA of the OWASP website server certificate -->
            <pin digest="SHA-256">YLh1dUR9y6Kja30RrAn7JKnbQG/uEtLMkBgFF2Fuihg=</pin>
            <!-- Hash of the public key (SubjectPublicKeyInfo of the X.509 certificate) of
            the Root CA of the OWASP website server certificate -->
            <pin digest="SHA-256">Vjs8r4z+80wjNcr1YKepWQboSIRi63WsWXhIMN+eWys=</pin>
        </pin-set>
    </domain-config>
</network-security-config>
```

Is important to understand the precedence of entries. If a value is not set in a `<domain-config\>` entry or in a parent `<domain-config\>`, the configurations in place will be based on the `<base-config\>`, and lastly if not defined in this entry, the default configuration will be used.

The default configuration for apps targeting Android 9 (API level 28) and higher is as follows:

```xml
<base-config cleartextTrafficPermitted="false">
    <trust-anchors>
        <certificates src="system" />
    </trust-anchors>
</base-config>
```

The default configuration for apps targeting Android 7.0 (API level 24) to Android 8.1 (API level 27) is as follows:

```xml
<base-config cleartextTrafficPermitted="true">
    <trust-anchors>
        <certificates src="system" />
    </trust-anchors>
</base-config>
```

The default configuration for apps targeting Android 6.0 (API level 23) and lower is as follows:

```xml
<base-config cleartextTrafficPermitted="true">
    <trust-anchors>
        <certificates src="system" />
        <certificates src="user" />
    </trust-anchors>
</base-config>
```

#### Dynamic Analysis

You can test the Network Security Configuration settings of a target app by using a dynamic approach, typically using an interception proxy such as Burp. However, it might be possible that you're not able to see the traffic at first, e.g. when testing an app targeting Android 7.0 (API level 24) or higher and effectively applying the Network Security Configuration. In that situation, you should patch the Network Security Configuration file. You'll find the necessary steps in section "[Bypassing the Network Security Configuration](0x05b-Basic-Security_Testing.md#bypassing-the-network-security-configuration "Bypassing the Network Security Configuration")" in the "Android Basic Security Testing" chapter.

There might still be scenarios where this is not needed and you can still do MITM attacks without patching:

- When the app is running on an Android device with Android 7.0 (API level 24) onwards, but the app targets API levels below 24, it will not use the Network Security Configuration file. Instead, the app will still trust any user supplied CAs.
- When the app is running on an Android device with Android 7.0 (API level 24) onwards and there is no custom Network Security Configuration implemented in the app.

### Testing the Security Provider (MSTG-NETWORK-6)

#### Overview

Android relies on a security provider to provide SSL/TLS-based connections. The problem with this kind of security provider (one example is [OpenSSL](https://www.openssl.org/news/vulnerabilities.html "OpenSSL Vulnerabilities")), which comes with the device, is that it often has bugs and/or vulnerabilities.
To avoid known vulnerabilities, developers need to make sure that the application will install a proper security provider.
Since July 11, 2016, Google [has been rejecting Play Store application submissions](https://support.google.com/faqs/answer/6376725?hl=en "How to address OpenSSL vulnerabilities in your apps") (both new applications and updates) that use vulnerable versions of OpenSSL.

#### Static Analysis

Applications based on the Android SDK should depend on GooglePlayServices. For example, in the gradle build file, you will find `compile 'com.google.android.gms:play-services-gcm:x.x.x'` in the dependencies block. You need to make sure that the `ProviderInstaller` class is called with either `installIfNeeded` or `installIfNeededAsync`. `ProviderInstaller` needs to be called by a component of the application as early as possible. Exceptions thrown by these methods should be caught and handled correctly.
If the application cannot patch its security provider, it can either inform the API of its less secure state or restrict user actions (because all HTTPS traffic should be deemed riskier in this situation).

Here are two [examples from the Android Developer documentation](https://developer.android.com/training/articles/security-gms-provider.html "Updating Your Security Provider to Protect Against SSL Exploits") that show how to update Security Provider to prevent SSL exploits. In both cases, the developer needs to handle the exceptions properly, and reporting to the backend when the application is working with an unpatched security provider may be wise.

Patching Synchronously:

```java
//this is a sync adapter that runs in the background, so you can run the synchronous patching.
public class SyncAdapter extends AbstractThreadedSyncAdapter {

  ...

  // This is called each time a sync is attempted; this is okay, since the
  // overhead is negligible if the security provider is up-to-date.
  @Override
  public void onPerformSync(Account account, Bundle extras, String authority,
      ContentProviderClient provider, SyncResult syncResult) {
    try {
      ProviderInstaller.installIfNeeded(getContext());
    } catch (GooglePlayServicesRepairableException e) {

      // Indicates that Google Play services is out of date, disabled, etc.

      // Prompt the user to install/update/enable Google Play services.
      GooglePlayServicesUtil.showErrorNotification(
          e.getConnectionStatusCode(), getContext());

      // Notify the SyncManager that a soft error occurred.
      syncResult.stats.numIOExceptions++;
      return;

    } catch (GooglePlayServicesNotAvailableException e) {
      // Indicates a non-recoverable error; the ProviderInstaller is not able
      // to install an up-to-date Provider.

      // Notify the SyncManager that a hard error occurred.
      //in this case: make sure that you inform your API of it.
      syncResult.stats.numAuthExceptions++;
      return;
    }

    // If this is reached, you know that the provider was already up-to-date,
    // or was successfully updated.
  }
}
```

Patching Asynchronously:

```java
//This is the mainactivity/first activity of the application that's there long enough to make the async installing of the securityprovider work.
public class MainActivity extends Activity
    implements ProviderInstaller.ProviderInstallListener {

  private static final int ERROR_DIALOG_REQUEST_CODE = 1;

  private boolean mRetryProviderInstall;

  //Update the security provider when the activity is created.
  @Override
  protected void onCreate(Bundle savedInstanceState) {
    super.onCreate(savedInstanceState);
    ProviderInstaller.installIfNeededAsync(this, this);
  }

  /**
   * This method is only called if the provider is successfully updated
   * (or is already up-to-date).
   */
  @Override
  protected void onProviderInstalled() {
    // Provider is up-to-date, app can make secure network calls.
  }

  /**
   * This method is called if updating fails; the error code indicates
   * whether the error is recoverable.
   */
  @Override
  protected void onProviderInstallFailed(int errorCode, Intent recoveryIntent) {
    if (GooglePlayServicesUtil.isUserRecoverableError(errorCode)) {
      // Recoverable error. Show a dialog prompting the user to
      // install/update/enable Google Play services.
      GooglePlayServicesUtil.showErrorDialogFragment(
          errorCode,
          this,
          ERROR_DIALOG_REQUEST_CODE,
          new DialogInterface.OnCancelListener() {
            @Override
            public void onCancel(DialogInterface dialog) {
              // The user chose not to take the recovery action
              onProviderInstallerNotAvailable();
            }
          });
    } else {
      // Google Play services is not available.
      onProviderInstallerNotAvailable();
    }
  }

  @Override
  protected void onActivityResult(int requestCode, int resultCode,
      Intent data) {
    super.onActivityResult(requestCode, resultCode, data);
    if (requestCode == ERROR_DIALOG_REQUEST_CODE) {
      // Adding a fragment via GooglePlayServicesUtil.showErrorDialogFragment
      // before the instance state is restored throws an error. So instead,
      // set a flag here, which will cause the fragment to delay until
      // onPostResume.
      mRetryProviderInstall = true;
    }
  }

  /**
   * On resume, check to see if we flagged that we need to reinstall the
   * provider.
   */
  @Override
  protected void onPostResume() {
    super.onPostResult();
    if (mRetryProviderInstall) {
      // We can now safely retry installation.
      ProviderInstall.installIfNeededAsync(this, this);
    }
    mRetryProviderInstall = false;
  }

  private void onProviderInstallerNotAvailable() {
    // This is reached if the provider cannot be updated for some reason.
    // App should consider all HTTP communication to be vulnerable, and take
    // appropriate action (e.g. inform backend, block certain high-risk actions, etc.).
  }
}

```

Make sure that NDK-based applications bind only to a recent and properly patched library that provides SSL/TLS functionality.

#### Dynamic Analysis

When you have the source code:

- Run the application in debug mode, then create a breakpoint where the app will first contact the endpoint(s).
- Right click the highlighted code and select `Evaluate Expression`.
- Type `Security.getProviders()` and press enter.
- Check the providers and try to find `GmsCore_OpenSSL`, which should be the new top-listed provider.

When you do not have the source code:

- Use Xposed to hook into the `java.security` package, then hook into `java.security.Security` with the method `getProviders` (with no arguments). The return value will be an array of `Provider`.
- Determine whether the first provider is `GmsCore_OpenSSL`.

#### References

#### OWASP Mobile Top 10 2016

- M3 - Insecure Communication - <https://www.owasp.org/index.php/Mobile_Top_10_2016-M3-Insecure_Communication>

##### OWASP MASVS

- MSTG-NETWORK-2: "The TLS settings are in line with current best practices, or as close as possible if the mobile operating system does not support the recommended standards."
- MSTG-NETWORK-3: "The app verifies the X.509 certificate of the remote endpoint when the secure channel is established. Only certificates signed by a trusted CA are accepted."
- MSTG-NETWORK-4: "The app either uses its own certificate store or pins the endpoint certificate or public key, and subsequently does not establish connections with endpoints that offer a different certificate or key, even if signed by a trusted CA."
- MSTG-NETWORK-6: "The app only depends on up-to-date connectivity and security libraries."

##### CWE

- CWE-295 - Improper Certificate Validation - <https://cwe.mitre.org/data/definitions/295.html>
- CWE-296 - Improper Following of a Certificate's Chain of Trust - <https://cwe.mitre.org/data/definitions/296.html>
- CWE-297 - Improper Validation of Certificate with Host Mismatch - <https://cwe.mitre.org/data/definitions/297.html>
- CWE-298 - Improper Validation of Certificate Expiration - <https://cwe.mitre.org/data/definitions/298.html>

##### Android Developer Documentation

- Network Security Config - <https://developer.android.com/training/articles/security-config>
- Network Security Config (cached alternative) - <https://webcache.googleusercontent.com/search?q=cache:hOONLxvMTwYJ:https://developer.android.com/training/articles/security-config+&cd=10&hl=nl&ct=clnk&gl=nl>

##### Xamarin Certificate Pinning

- Certificate and Public Key Pinning with Xamarin - <https://thomasbandt.com/certificate-and-public-key-pinning-with-xamarin>
- ServicePointManager - <https://msdn.microsoft.com/en-us/library/system.net.servicepointmanager(v=vs.110).aspx>

##### Cordova Certificate Pinning

- PhoneGap SSL Certificate Checker plugin - <https://github.com/EddyVerbruggen/SSLCertificateChecker-PhoneGap-Plugin>
