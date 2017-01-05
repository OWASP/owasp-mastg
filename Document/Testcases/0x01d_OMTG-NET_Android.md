## Android

### <a name="[OMTG-NET-001]"></a>OMTG-NET-001: Test for unencrypted sensitive data on the network

#### Overview

A functionality of most mobile applications requires sending or receiving information from services on the Internet. This reveals another surface of attacks aim at data on the way. It's possible for an attacker to sniff or even modify (MiTM attacks) an unencrypted information if he controls any part of network infrastructure (e.g. an WiFi Access Point) [1]. For this reason, developers should make a general rule, that any confidential data cannot be sent in a cleartext [2].

#### White-box Testing

Identify all external endpoints (backend APIs, third-party web services), which communicate with tested application and ensure that all those communication channels are encrypted.

#### Black-box Testing

The recommended approach is to intercept all network traffic coming to or from tested application and check if it is encrypted. A network traffic can be intercepted using one of the following approaches:

* Capture all network traffic, using [Tcpdump]. You can star live capturing via command:
```
adb shell "tcpdump -s 0 -w - | nc -l -p 1234"
adb forward tcp:1234 tcp:1234
```

Then you can display captured traffic in a human-readable way, using [Wireshark]
```
nc localhost 1234 | sudo wireshark -k -S -i –
```

* Capture all network traffic using intercept proxy, like [OWASP ZAP] or [Burp Suite]. If you're able to see any traffic without installing RootCA on your device, then it means that intercepted traffic is not encrypted.

It is important to capture all traffic (TCP and UDP), so you should run all possible functions of tested application after starting interception. This should include a process of patching application, because sending a patch to application via HTTP may allow an attacker to install any application on victim's device (MiTM attacks).

#### Remediation

Ensure that sensitive information is being sent via secure channels, e.g. [HTTPS] over HTTP, or [SSLSocket] for socket-level communication.

Some applications may use localhost address, or binding to INADDR_ANY for handling sensitive IPC, what is bad from security perspective, as this interface is accessible for other applications installed on a device. For such purpose developers should consider using secure [Android IPC mechanism].

#### OWASP MASVS

V5.1: "Sensitive data is encrypted on the network using TLS. The secure channel is used consistently throughout the app."

#### OWASP Mobile Top 10

M3 - Insecure Communication

#### CWE

[CWE 319]

#### References

- [1] https://cwe.mitre.org/data/definitions/319.html
- [2] https://developer.android.com/training/articles/security-tips.html#Networking


[Tcpdump]: http://www.androidtcpdump.com/
[Wireshark]: https://www.wireshark.org/download.html
[OWASP ZAP]: https://security.secure.force.com/security/tools/webapp/zapandroidsetup
[Burp Suite]: https://support.portswigger.net/customer/portal/articles/1841101-configuring-an-android-device-to-work-with-burp
[HTTPS]: https://developer.android.com/reference/javax/net/ssl/HttpsURLConnection.html
[SSLSocket]: https://developer.android.com/reference/javax/net/ssl/SSLSocket.html
[Android IPC mechanism]: https://developer.android.com/reference/android/app/Service.html
[CWE 319]: https://cwe.mitre.org/data/definitions/319.html


### <a name="OMTG-NET-003"></a>OMTG-NET-003: Test SSL Pinning

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
