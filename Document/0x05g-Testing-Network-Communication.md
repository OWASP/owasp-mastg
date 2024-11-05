---
masvs_category: MASVS-NETWORK
platform: android
---

# Android Network Communication

## Overview

Almost every Android app acts as a client to one or more remote services. As this network communication usually takes place over untrusted networks such as public Wi-Fi, classical network based-attacks become a potential issue.

Most modern mobile apps use variants of HTTP-based web services, as these protocols are well-documented and supported.

### Android Network Security Configuration

Starting on Android 7.0 (API level 24), Android apps can customize their network security settings using the so-called [Network Security Configuration](https://developer.android.com/training/articles/security-config) feature which offers the following key capabilities:

- **Cleartext traffic**: Protect apps from accidental usage of cleartext traffic (or enables it).
- **Custom trust anchors**: Customize which Certificate Authorities (CAs) are trusted for an app's secure connections. For example, trusting particular self-signed certificates or restricting the set of public CAs that the app trusts.
- **Certificate pinning**: Restrict an app's secure connection to particular certificates.
- **Debug-only overrides**: Safely debug secure connections in an app without added risk to the installed base.

If an app defines a custom Network Security Configuration, you can obtain its location by searching for `android:networkSecurityConfig` in the AndroidManifest.xml file.

```xml
<application android:networkSecurityConfig="@xml/network_security_config"
```

In this case the file is located at `@xml` (equivalent to /res/xml) and has the name "network_security_config" (which might vary). You should be able to find it as "res/xml/network_security_config.xml". If a configuration exists, the following event should be visible in the system logs (@MASTG-TECH-0009):

```bash
D/NetworkSecurityConfig: Using Network Security Config from resource network_security_config
```

The Network Security Configuration is [XML-based](https://developer.android.com/training/articles/security-config#FileFormat) and can be used to configure app-wide and domain-specific settings:

- `base-config` applies to all connections that the app attempts to make.
- `domain-config` overrides `base-config` for specific domains (it can contain multiple `domain` entries).

For example, the following configuration uses the `base-config` to prevent cleartext traffic for all domains. But it overrides that rule using a `domain-config`, explicitly allowing cleartext traffic for `localhost`.

```xml
<?xml version="1.0" encoding="utf-8"?>
<network-security-config>
    <base-config cleartextTrafficPermitted="false" />
    <domain-config cleartextTrafficPermitted="true">
        <domain>localhost</domain>
    </domain-config>
</network-security-config>
```

Learn more:

- ["A Security Analyst’s Guide to Network Security Configuration in Android P"](https://www.nowsecure.com/blog/2018/08/15/a-security-analysts-guide-to-network-security-configuration-in-android-p/)
- [Android Developers - Network Security Configuration](https://developer.android.com/training/articles/security-config)
- [Android Codelab - Network Security Configuration](https://developer.android.com/codelabs/android-network-security-config)

#### Default Configurations

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

#### Certificate Pinning

The Network Security Configuration can also be used to pin [declarative certificates](https://developer.android.com/training/articles/security-config.html#CertificatePinning "Certificate Pinning using Network Security Configuration") to specific domains. This is done by providing a `<pin-set>` in the Network Security Configuration, which is a set of digests (hashes) of the public key (`SubjectPublicKeyInfo`) of the corresponding X.509 certificate.

When attempting to establish a connection to a remote endpoint, the system will:

- Get and validate the incoming certificate.
- Extract the public key.
- Calculate a digest over the extracted public key.
- Compare the digest with the set of local pins.

If at least one of the pinned digests matches, the certificate chain will be considered valid and the connection will proceed.

```xml
<?xml version="1.0" encoding="utf-8"?>
<network-security-config>
    <domain-config>
        Use certificate pinning for OWASP website access including sub domains
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

!!! note "Expiration dates"
    If you ["set an expiration date"](https://developer.android.com/privacy-and-security/security-config#CertificatePinning), make sure to update your application in time. Otherwise pinning will **not** be performed any more after that date.

!!! warning "Technologies not using Network Security Configuration"
    If your application uses low level networking APIs or SDKs like Flutter, the Network Security Configuration might not be used by default.

### Certificate pinning without Android Network Security Configuration

If your application targets an Android version lower than Android 7.0 Nougat (SDK version 24), the Android Security Configuration is not available, and you need to implement certificate pinning manually.

#### TrustManager

Implementing certificate pinning can for example be done with the following steps:

- Obtain the certificate of the desired host(s).
- Make sure the certificate is in .bks format.
- Pin the certificate to an instance of the SSLContext used for the connection.

To analyze the correct implementation of certificate pinning, the HTTP client should load the KeyStore:

```java
InputStream in = resources.openRawResource(certificateRawResource);
keyStore = KeyStore.getInstance("BKS");
keyStore.load(resourceStream, password);
```

Once the KeyStore has been loaded, you can use the TrustManager that trusts the CAs in the KeyStore:

```java
String tmfAlgorithm = TrustManagerFactory.getDefaultAlgorithm();
TrustManagerFactory tmf = TrustManagerFactory.getInstance(tmfAlgorithm);
tmf.init(keyStore);
// Create an SSLContext that uses the TrustManager
// SSLContext context = SSLContext.getInstance("TLSv1.3");
sslContext.init(null, tmf.getTrustManagers(), null);
```

#### Network Libraries

Applications that use third-party networking libraries may utilize the libraries' certificate pinning functionality. For example, [okhttp](https://square.github.io/okhttp/features/https/#certificate-pinning-kt-java) can be set up with the `CertificatePinner` as follows:

```java
OkHttpClient client = new OkHttpClient.Builder()
        .certificatePinner(new CertificatePinner.Builder()
            .add("example.com", "sha256/UwQAapahrjCOjYI3oLUx5AQxPBR02Jz6/E2pt0IeLXA=")
            .build())
        .build();
```

#### WebViews

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

#### Xamarin Applications

Applications developed in Xamarin will typically use `ServicePointManager` to implement pinning.

Normally a function is created to check the certificate(s) and return the boolean value to the method `ServerCertificateValidationCallback`:

```cs
[Activity(Label = "XamarinPinning", MainLauncher = true)]
    public class MainActivity : Activity
    {
        // SupportedPublicKey - Hexadecimal value of the public key.
        // Use GetPublicKeyString() method to determine the public key of the certificate we want to pin. Uncomment the debug code in the ValidateServerCertificate function a first time to determine the value to pin.
        private const string SupportedPublicKey = "3082010A02820101009CD30CF05AE52E47B7725D3783B..."; // Shortened for readability

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

Sample Xamarin app with the previous example can be obtained on the [MASTG repository](https://github.com/OWASP/owasp-mastg/raw/master/Samples/Android/02_CertificatePinning/certificatePinningXamarin.apk "Xamarin app with certificate pinning")


After decompressing the APK file, use a .NET decompiler like dotPeak, ILSpy or dnSpy to decompile the app dlls stored inside the 'Assemblies' folder and confirm the usage of the ServicePointManager.

Learn more:

- Certificate and Public Key Pinning with Xamarin - <https://thomasbandt.com/certificate-and-public-key-pinning-with-xamarin>
- ServicePointManager - <https://msdn.microsoft.com/en-us/library/system.net.servicepointmanager(v=vs.110).aspx>

#### Cordova Applications

Hybrid applications based on Cordova do not support Certificate Pinning natively, so plugins are used to achieve this. The most common one is [PhoneGap SSL Certificate Checker](https://github.com/EddyVerbruggen/SSLCertificateChecker-PhoneGap-Plugin "PhoneGap SSL Certificate Checker plugin"). The `check` method is used to confirm the fingerprint and callbacks will determine the next steps.

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

### Security Provider

Android relies on a [security provider](https://developer.android.com/training/articles/security-gms-provider.html "Update your security provider to protect against SSL exploits") to provide SSL/TLS-based connections. The problem with this kind of security provider (one example is [OpenSSL](https://www.openssl.org/news/vulnerabilities.html "OpenSSL Vulnerabilities")), which comes with the device, is that it often has bugs and/or vulnerabilities.

To avoid known vulnerabilities, developers need to make sure that the application will install a proper security provider.
Since July 11, 2016, Google [has been rejecting Play Store application submissions](https://support.google.com/faqs/answer/6376725?hl=en "How to address OpenSSL vulnerabilities in your apps") (both new applications and updates) that use vulnerable versions of OpenSSL.
