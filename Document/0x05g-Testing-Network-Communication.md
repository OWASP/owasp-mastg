## Testing Network Communcation

### Testing for Unencrypted Sensitive Data on the Network

#### Overview

A functionality of most mobile applications requires sending or receiving information from services on the Internet. This reveals another surface of attacks aimed at data on the way. It's possible for an attacker to sniff or even modify (MiTM attacks) an unencrypted information if he controls any part of network infrastructure (e.g. an WiFi Access Point) [1]. For this reason, developers should make a general rule, that any confidential data cannot be sent in a cleartext [2].

#### White-box Testing

Identify all external endpoints (backend APIs, third-party web services), which communicate with tested application and ensure that all those communication channels are encrypted.

#### Black-box Testing

The recommended approach is to intercept all network traffic coming to or from tested application and check if it is encrypted. A network traffic can be intercepted using one of the following approaches:

* Capture all network traffic, using Tcpdump. You can begin live capturing via command:
```
adb shell "tcpdump -s 0 -w - | nc -l -p 1234"
adb forward tcp:1234 tcp:1234
```

Then you can display captured traffic in a human-readable way, using Wireshark
```
nc localhost 1234 | sudo wireshark -k -S -i –
```

* Capture all network traffic using intercept proxy, like OWASP ZAP [3] or Burp Suite [4] and observe whether all requests are using HTTPS instead of HTTP.

> Please note, that some applications may not work with proxies like Burp or ZAP (because of customized HTTP/HTTPS implementation, or Cert Pinning). In such case you may use a VPN server to forward all traffic to your Burp/ZAP proxy. You can easily do this, using Vproxy.

It is important to capture all traffic (TCP and UDP), so you should run all possible functions of tested application after starting interception. This should include a process of patching application, because sending a patch to application via HTTP may allow an attacker to install any application on victim's device (MiTM attacks).

#### Remediation

Ensure that sensitive information is being sent via secure channels, using HTTPS [5], or SSLSocket [6] for socket-level communication using TLS.

> Please be aware that `SSLSocket` **does not** verify hostname. The hostname verification should be done by using `getDefaultHostnameVerifier()` with expected hostname. Here [7] you can find an example of correct usage.

Some applications may use localhost address, or binding to INADDR_ANY for handling sensitive IPC, what is bad from security perspective, as this interface is accessible for other applications installed on a device. For such purpose developers should consider using secure Android IPC mechanism [8].

#### OWASP MASVS

V5.1: "Sensitive data is encrypted on the network using TLS. The secure channel is used consistently throughout the app."

#### CWE

CWE 319 - Cleartext Transmission of Sensitive Information - https://cwe.mitre.org/data/definitions/319.html

#### OWASP Mobile Top 10 2014

M3 - Insufficient Transport Layer Protection - https://www.owasp.org/index.php/Mobile_Top_10_2014-M3

#### References

- [1] https://cwe.mitre.org/data/definitions/319.html
- [2] https://developer.android.com/training/articles/security-tips.html#Networking
- [3] https://security.secure.force.com/security/tools/webapp/zapandroidsetup
- [4] https://support.portswigger.net/customer/portal/articles/1841101-configuring-an-android-device-to-work-with-burp
- [5] https://developer.android.com/reference/javax/net/ssl/HttpsURLConnection.html
- [6] https://developer.android.com/reference/javax/net/ssl/SSLSocket.html
- [7] https://developer.android.com/training/articles/security-ssl.html#WarningsSslSocket
- [8] https://developer.android.com/reference/android/app/Service.html

#### Tools

* Tcpdump - http://www.androidtcpdump.com/
* Wireshark - https://www.wireshark.org/
* OWASP ZAP - https://www.owasp.org/index.php/OWASP_Zed_Attack_Proxy_Project
* Burp Suite - https://portswigger.net/burp/
* Vproxy - https://github.com/B4rD4k/Vproxy

### Verifying the TLS Settings

#### Overview

Using encryption is essential when you are sending confidential data. However, encryption can defend your privacy, only if it uses enough strong cryptography. To reach this goal SSL-based services should not offer the possibility to choose weak cipher suite. A cipher suite is specified by an encryption protocol (e.g. DES, RC4, AES), the encryption key length (e.g. 40, 56, or 128 bits), and a hash algorithm (e.g. SHA, MD5) used for integrity checking. To ensure, that your encryption cannot be easily defeated, you should verify your TLS configuration that it does not use any weak cipher/protocol/key [1].



#### Static Analysis

Static analysis is not applicable for this point.

#### Dynamic Analysis

After identifying all servers communicating with your application (e.g. using Tcpdump, or Burp Suite) you should verify if a server/-s allow for using weak cipher/protocol/key. It can be done, using different tools:

* Qualys SSL Labs: put server's URL in the following online scanner https://www.ssllabs.com/ssltest/ and click submit.
* sslyze: via following command:

```
sslyze --regular www.example.com:443
```

#### Remediation

To properly configure transport layer protection for network communication, please follow the OWASP TLS cheat sheet [2].

#### References

##### OWASP Mobile Top 10 2014

M3 - Insufficient Transport Layer Protection - https://www.owasp.org/index.php/Mobile_Top_10_2014-M3

##### OWASP MASVS

- V5.2: "The TLS settings are in line with current best practices, or as close as possible if the mobile operating system does not support the recommended standards."

##### CWE

- CWE-327 - Use of a Broken or Risky Cryptographic Algorithm - https://cwe.mitre.org/data/definitions/327.html

##### Info

- [1] Testing for Weak SSL/TLS Ciphers - https://www.owasp.org/index.php/Testing_for_Weak_SSL/TLS_Ciphers,_Insufficient_Transport_Layer_Protection_(OTG-CRYPST-001)
- [2] Transport Layer Protection Cheat Sheet - https://www.owasp.org/index.php/Transport_Layer_Protection_Cheat_Sheet

##### Tools

* Qualys SSL Labs - https://www.ssllabs.com/ssltest/
* sslyze - https://github.com/nabla-c0d3/sslyze

### Testing Endpoint Identify Verification

#### Overview

Using TLS for transporting sensitive information over the network is essential from security point of view. However, implementing a mechanism of encrypted communication between mobile application and backend API is not a trivial task. Developers often decides for easier, but less secure (e.g. accepting any certificate) solutions to ease a development process what often is not fixed after going on production [1], exposing at the same time an application to man-in-the-middle attacks [2].

#### White-box Testing

There are 2 main issues related with validating TLS connection: the first one is verification if a certificate comes from trusted source and the second one is a check whether the endpoint server presents the right certificate [3].

##### Verifying server certificate

A mechanism responsible for verifying conditions to establish a trusted connection in Android is called `TrustedManager`. Conditions to be checked at this point, are the following:

* is the certificate signed by a "trusted" CA?
* is the certificate expired?
* Is the certificate self-sgined?

You should look in a code if there are control checks of aforementioned conditions. For example, the following code will accept any certificate:

```
TrustManager[] trustAllCerts = new TrustManager[] {
new X509TrustManager()
{

    public java.security.cert.X509Certificate[] getAcceptedIssuers()
    {
        return new java.security.cert.X509Certificate[] {};
    }
    public void checkClientTrusted(X509Certificate[] chain,
    String authType) throws CertificateException
    {

    }
    public void checkServerTrusted(X509Certificate[] chain,
    String authType) throws CertificateException
    {

    }

}};

context.init(null, trustAllCerts, new SecureRandom());
```


##### Hostname verification

Another security fault in TLS implementation is lack of hostname verification. A development environment usually uses some internal addresses instead of valid domain names, so developers often disable hostname verification (or force an application to allow any hostname) and simply forget to change it when their application goes to production. The following code is responsible for disabling hostname verification:

```
final static HostnameVerifier NO_VERIFY = new HostnameVerifier()
{
    public boolean verify(String hostname, SSLSession session)
    {
              return true;
    }
};
```

It's also possible to accept any hostname using a built-in `HostnameVerifier`:

```
HostnameVerifier NO_VERIFY = org.apache.http.conn.ssl.SSLSocketFactory
                             .ALLOW_ALL_HOSTNAME_VERIFIER;
```

Ensure that your application verifies a hostname before setting trusted connection.


#### Black-box Testing

Improper certificate verification may be found using static or dynamic analysis.

* Static analysis approach is to decompile an application and simply look in a code for TrustManager and HostnameVerifier usage. You can find insecure usage examples in a "White-box Testing" section above. Such checks of improper certificate verification, may be done automatically, using a tool called MalloDroid [4]. It simply decompiles an application and warns you if it finds something suspicious. To run it, simply type this command:

```
./mallodroid.py -f ExampleApp.apk -d ./outputDir
```

Now, you should be warned if any suspicious code was found by MalloDroid and in `./outputDir` you will find decompiled application for further manual analysis.

* Dynamic analysis approach will require usage of intercept proxy, e.g. Burp Suite. To test improper certificate verification, you should go through following control checks:

 1) Self-signed certificate.

  In Burp go to Proxy -> Options tab, go to Proxy Listeners section, highlight you listener and click Edit button. Then go to Certificate tab and check 'Use a self-signed certificate' and click Ok. Now, run your application. If you are able to see HTTPS traffic, then it means your application is accepting self-signed certificates.

 2) Accepting invalid certificate.

  In Burp go to Proxy -> Options tab, go to Proxy Listeners section, highlight you listener and click Edit button. Then go to Certificate tab, check 'Generate a CA-signed certificate with a specific hostname' and type hostname of a backend server. Now, run your application. If you are able to see HTTPS traffic, then it means your application is accepting any certificate.

 3) Accepting wrong hostname.

  In Burp go to Proxy -> Options tab, go to Proxy Listeners section, highlight you listener and click Edit button. Then go to Certificate tab, check 'Generate a CA-signed certificate with a specific hostname' and type invalid hostname, e.g. 'example.org'. Now, run your application. If you are able to see HTTPS traffic, then it means your application is accepting any hostname.

> **Note**, if you are interested in further MITM analysis or you face any problems with configuration of your intercept proxy, you may consider using Tapioca [6]. It's a CERT preconfigured VM appliance [7] for performing MITM analysis of software. All you have to do is deploy a tested application on emulator and start capturing traffic [8].

#### Remediation

Ensure, that the hostname and certificate is verified correctly. You can find a help how to overcome common TLS certificate issues here [2].

#### OWASP MASVS

V5.3: "	The app verifies the X.509 certificate of the remote endpoint when the secure channel is established. Only certificates signed by a valid CA are accepted."

#### CWE

CWE 295 - Improper Certificate Validation - https://cwe.mitre.org/data/definitions/295.html
CWE 296 - Improper Following of a Certificate's Chain of Trust - https://cwe.mitre.org/data/definitions/296.html
CWE 297 - Improper Validation of Certificate with Host Mismatch - https://cwe.mitre.org/data/definitions/297.html
CWE 298 - Improper Validation of Certificate Expiration - https://cwe.mitre.org/data/definitions/298.html

#### OWASP Mobile Top 10 2014

M3 - Insufficient Transport Layer Protection - https://www.owasp.org/index.php/Mobile_Top_10_2014-M3

#### References

- [1] https://www.owasp.org/images/7/77/Hunting_Down_Broken_SSL_in_Android_Apps_-_Sascha_Fahl%2BMarian_Harbach%2BMathew_Smith.pdf
- [2] https://cwe.mitre.org/data/definitions/295.html
- [3] https://developer.android.com/training/articles/security-ssl.html
- [4] https://github.com/sfahl/mallodroid
- [5] https://support.portswigger.net/customer/portal/articles/1841101-configuring-an-android-device-to-work-with-burp
- [6] https://insights.sei.cmu.edu/cert/2014/08/-announcing-cert-tapioca-for-mitm-analysis.html
- [7] http://www.cert.org/download/mitm/CERT_Tapioca.ova
- [8] https://insights.sei.cmu.edu/cert/2014/09/-finding-android-ssl-vulnerabilities-with-cert-tapioca.html

### Testing Custom Certificate Stores and SSL Pinning

#### Overview

Certificate pinning allows to hard-code in the client the certificate that is known to be used by the server. This technique is used to reduce the threat of a rogue CA and CA compromise. Pinning the server’s certificate take the CA out of games. Mobile applications that implements certificate pinning only have to connect to a limited numbers of server, so a small list of trusted CA can be hard-coded in the application.

#### White-box Testing

The process to implement the SSL pinning involves three main steps outlined below:

1. Obtain a certificate for the desired host
1. Make sure certificate is in .bks format
1. Pin the certificate to an instance of the default Apache Httpclient.

To analyze the correct implementations of the SSL pinning the HTTP client should:

1. Load the keystore:

```java
InputStream in = resources.openRawResource(certificateRawResource);
keyStore = KeyStore.getInstance("BKS");
keyStore.load(resourceStream, password);
```

Once the keystore is loaded we can use the TrustManager that trusts the CAs in our KeyStore :

```java
String tmfAlgorithm = TrustManagerFactory.getDefaultAlgorithm();
TrustManagerFactory tmf = TrustManagerFactory.getInstance(tmfAlgorithm);
tmf.init(keyStore);
Create an SSLContext that uses the TrustManager
// SSLContext context = SSLContext.getInstance("TLS");
sslContext.init(null, tmf.getTrustManagers(), null);
```

#### Black-box Testing

Black-box Testing can be performed by launching a MITM attack using your prefered Web Proxy to intercept the traffic exchanged between client (mobile application) and the backend server. If the Proxy is unable to intercept the HTTP requests/responses, the SSL pinning is correctly implemented.

#### Remediation

The SSL pinning process should be implemented as described on the static analysis section.

#### References

- Setting Burp Suite as a proxy for Android Devices : https://support.portswigger.net/customer/portal/articles/1841101-configuring-an-android-device-to-work-with-burp)
- OWASP - Certificate Pinning for Android :  https://www.owasp.org/index.php/Certificate_and_Public_Key_Pinning#Android


### Verifying that Critical Operations Use Secure Communication Channels

#### Overview

[Provide a general description of the issue.]

#### Static Analysis

[Describe how to assess this given either the source code or installer package (APK/IPA/etc.), but without running the app. Tailor this to the general situation (e.g., in some situations, having the decompiled classes is just as good as having the original source, in others it might make a bigger difference). If required, include a subsection about how to test with or without the original sources.]

[Use the &lt;sup&gt; tag to reference external sources, e.g. Meyer's recipe for tomato soup<sup>[1]</sup>.]

##### With Source Code

##### Without Source Code

#### Dynamic Analysis

[Describe how to test for this issue by running and interacting with the app. This can include everything from simply monitoring network traffic or aspects of the app’s behavior to code injection, debugging, instrumentation, etc.]

#### Remediation

[Describe the best practices that developers should follow to prevent this issue.]

#### References

##### OWASP Mobile Top 10 2014

* MX - Title - Link
* M3 - Insufficient Transport Layer Protection - https://www.owasp.org/index.php/Mobile_Top_10_2014-M3

##### OWASP MASVS

- VX.Y: "Requirement text, e.g. 'the keyboard cache is disabled on text inputs that process sensitive data'."

##### CWE

- CWE-XXX - Title
- CWE-312 - Cleartext Storage of Sensitive Information

##### Info

- [1] Meyer's Recipe for Tomato Soup - http://www.finecooking.com/recipes/meyers-classic-tomato-soup.aspx
- [2] Another Informational Article - http://www.securityfans.com/informational_article.html

