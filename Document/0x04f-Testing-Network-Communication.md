## Testing Network Communication

Practically every network-connected mobile app uses the Hypertext Transfer Protocol (HTTP) or HTTP over Transport Layer Security (TLS), HTTPS, to send and receive data to and from remote endpoints. Consequently, network-based attacks (such as packet sniffing and man-in-the-middle-attacks) are a problem. In this chapter we discuss potential vulnerabilities, testing techniques, and best practices concerning the network communication between mobile apps and their endpoints.

### Testing Data Encryption on the Network

#### Overview

One of the core mobile app functions is sending/receiving data over untrusted networks like the Internet. If the data is not properly protected in transit, an attacker with access to any part of the network infrastructure (e.g., a Wi-Fi access point) may intercept, read, or modify it. This is why plaintext network protocols are rarely advisable.

The vast majority of apps rely on HTTP for communication with the backend. HTTPS wraps HTTP in an encrypted connection (the acronym HTTPS originally referred to HTTP over Secure Socket Layer (SSL); SSL is the deprecated predecessor of TLS). TLS allows authentication of the backend service and ensures confidentiality and integrity of the network data.

#### Static Analysis

Identify all API/web service requests in the source code and ensure that no plain HTTP URLs are requested. Make sure that sensitive information is sent over secure channels by using [HttpsURLConnection](https://developer.android.com/reference/javax/net/ssl/HttpsURLConnection.html "HttpsURLConnection") or [SSLSocket](https://developer.android.com/reference/javax/net/ssl/SSLSocket.html "SSLSocket") (for socket-level communication using TLS).

Be aware that `SSLSocket` **doesn't** verify the hostname. Use `getDefaultHostnameVerifier` to verify the hostname. The Android developer documentation includes a [code example](https://developer.android.com/training/articles/security-ssl.html#WarningsSslSocket "Warnings About Using SSLSocket Directly").

#### Dynamic Analysis

Intercept the tested application's incoming and outgoing network traffic and make sure that this traffic is encrypted. You can intercept network traffic in any of the following ways:

- Capture all HTTP and Websocket traffic with an interception proxy like [OWASP ZAP](https://security.secure.force.com/security/tools/webapp/zapandroidsetup "OWASP ZAP") or [Burp Suite Professional](https://support.portswigger.net/customer/portal/articles/1841101-configuring-an-android-device-to-work-with-burp "Configuring an Android device to work with Burp") and make sure all requests are made via HTTPS instead of HTTP.

Interception proxies like Burp and OWASP ZAP will show HTTP traffic only. You can, however, use Burp plugins such as [Burp-non-HTTP-Extension](https://github.com/summitt/Burp-Non-HTTP-Extension) and [mitm-relay](https://github.com/jrmdev/mitm_relay) to decode and visualize communication via XMPP and other protocols.

> Some applications may not work with proxies like Burp and ZAP because of Certificate Pinning. In such a scenario, please check "Testing Custom Certificate Stores and SSL Pinning". Tools like Vproxy can be used to redirect all HTTP(S) traffic to your machine to sniff and investigate it for unencrypted requests.

- Capture all network traffic with Tcpdump. Consider this when Burp or OWASP ZAP do not recognize protocols (e.g. XMPP). You can begin live capturing via the command:

```bash
adb shell "tcpdump -s 0 -w - | nc -l -p 1234"
adb forward tcp:1234 tcp:1234
```

You can display the captured traffic in a human-readable format with Wireshark. Figure out which protocols are used and whether they are unencrypted. Capturing all traffic (TCP and UDP) is important, so you should execute all functions of the tested application after you've intercepted it.

#### References

##### OWASP Mobile Top 10 2016

- M3 - Insecure Communication - https://www.owasp.org/index.php/Mobile_Top_10_2016-M3-Insecure_Communication

##### OWASP MASVS

- V5.1: "Data is encrypted on the network with TLS. The secure channel is used consistently throughout the app."

##### CWE

- CWE-319 - Cleartext Transmission of Sensitive Information

##### Tools

- Tcpdump - http://www.androidtcpdump.com/
- Wireshark - https://www.wireshark.org/
- OWASP ZAP - https://www.owasp.org/index.php/OWASP_Zed_Attack_Proxy_Project
- Burp Suite - https://portswigger.net/burp/
- Vproxy - https://github.com/B4rD4k/Vproxy


### Verifying the TLS Settings

#### Overview

Ensuring proper TLS configuration on the server side is also important. SSL is deprecated and should no longer be used. TLS v1.2 and v1.3 are considered secure, but many services still allow TLS v1.0 and v1.1 for compatibility with older clients.

When both the client and server are controlled by the same organization and used only for communicating with one another, you can increase security by [hardening the configuration](https://dev.ssllabs.com/projects/best-practices/ "Qualys SSL/TLS Deployment Best Practices").

If a mobile application connects to a specific server, its networking stack can be tuned to ensure the highest possible security level for the server's configuration. Lack of support in the underlying operating system may force the mobile application to use a weaker configuration.

For example, the popular Android networking library okhttp uses the following preferred set of cipher suites, but these are only available on Android versions 7.0 and later:

- `TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256`
- `TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256`
- `TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384`
- `TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384`
- `TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256`
- `TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256`

To support earlier versions of Android, it adds a few ciphers that are considered less secure, for example, `TLS_RSA_WITH_3DES_EDE_CBC_SHA`.

Similarly, the iOS ATS (App Transport Security) configuration requires one of the following ciphers:

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

#### Static Analysis

The configuration file of the web server or reverse proxy at which the HTTPS connection terminates is required for static analysis. Make sure that the server is configured according to best practices. See also the [OWASP Transport Layer Protection cheat sheet](https://www.owasp.org/index.php/Transport_Layer_Protection_Cheat_Sheet "Transport Layer Protection Cheat Sheet") and the [Qualys SSL/TLS Deployment Best Practices](https://dev.ssllabs.com/projects/best-practices/ "Qualys SSL/TLS Deployment Best Practices").

#### Dynamic Analysis

After you identify all the endpoints your application is communicating with (using, for example, an interception proxy), you should [find out whether the endpoints allow weak ciphers, protocols, or keys](https://www.owasp.org/index.php/Testing_for_Weak_SSL/TLS_Ciphers,_Insufficient_Transport_Layer_Protection_(OTG-CRYPST-001\) "Testing for Weak SSL/TLS Ciphers, Insufficient Transport Layer Protection (OTG-CRYPST-001)"). You can do this with any of the following tools:

- testssl.sh:

The GitHub repo for testssl.sh offers a compiled openssl version that supports **all cipher suites and protocols, including SSLv2**.

```
$ ./testssl.sh --openssl bin/openssl.Linux.x86_64 yoursite.com
```

The tool also helps you identify misconfigurations and vulnerabilities by highlighting them in red. If you want to store the report, preserving its color and format, use `aha`:

```
$ ./testssl.sh --openssl bin/openssl.Linux.x86_64 yoursite.com | aha > output.html
```

This will give you an HTML document that will match the CLI output.

- O-Saft (OWASP SSL Advanced Forensic Tool):

There are [several O-Saft options](https://www.owasp.org/index.php/O-Saft/Documentation#COMMANDS "O-Saft various tests. Run o-saft with the following command line flags to  verify certificates, ciphers, and SSL/TLS connections:

```
perl o-saft.pl +check www.example.com:443
```

You can run O-Saft in GUI mode with the following command:

```
o-saft.tcl
```

#### References

##### OWASP Mobile Top 10 2016

- M3 - Insecure Communication - https://www.owasp.org/index.php/Mobile_Top_10_2016-M3-Insecure_Communication

##### OWASP MASVS

- V5.2: "The TLS settings are in line with current best practices or as close as possible (if the mobile operating system doesn’t support the recommended standards)."

##### CWE

- CWE-327 - Use of a Broken or Risky Cryptographic Algorithm - https://cwe.mitre.org/data/definitions/327.html

##### Tools

- testssl.sh- https://testssl.sh
- O-Saft - https://www.owasp.org/index.php/O-Saft


### Making Sure that Critical Operations Use Secure Communication Channels

#### Overview

For sensitive applications like banking apps, [OWASP MASVS](https://github.com/OWASP/owasp-masvs/blob/master/Document/0x03-Using_the_MASVS.md "The Mobile Application Security Verification Standard") introduces "Defense in Depth" verification levels. The critical operations (e.g., user enrollment and account recovery) of such applications are some of the most attractive targets to attackers. This requires implementation of advanced security controls, such as additional channels (e.g., SMS and e-mail) to confirm user actions. 

#### Static Analysis

Review the code and identify the parts that refer to critical operations. Make sure that additional channels are used for such operation. The following are examples of additional verification channels:

- Token (e.g., RSA token, yubikey);
- Push notification (e.g., Google Prompt);
- SMS;
- E-mail;
- Data from another website you visited or scanned;
- Data from a physical letter or physical entry point (e.g., data you receive only after signing a document at a bank).

#### Dynamic Analysis

Identify all of the tested application's critical operations (e.g., user enrollment, account recovery, and money transfer). Ensure that each critical operation requires at least one additional channel (e.g., SMS, e-mail, or token). Make sure that directly calling the function bypasses usage of these channels.

#### Remediation

Make sure that critical operations enforce the use of at least one additional channel to confirm user actions. These channels must not be bypassed when executing critical operations. If you're going to implement an additional factor to verify the user's identity, consider [Infobip 2FA library](https://2-fa.github.io/libraries/android-library.html "Infobip 2FA library") or one-time passcodes (OTP) via [Google Authenticator](https://github.com/google/google-authenticator-android "Google Authenticator for Android").

#### References

##### OWASP Mobile Top 10 2016
- M3 - Insecure Communication - https://www.owasp.org/index.php/Mobile_Top_10_2016-M3-Insecure_Communication

##### OWASP MASVS
- V5.5: "The app doesn't rely on a single insecure communication channel (e-mail or SMS) for critical operations such as enrollment and account recovery."

##### CWE
- CWE-308 - Use of Single-factor Authentication


### Man-in-the-Middle-Attacks on the Network Layer

We will first talk about an attack pattern that applies when you're security testing mobile applications: man-in-the-middle (MITM) attacks.

Performing dynamic analysis with an interception proxy can be straightforward if the app uses standard libraries and all communication is done via HTTP, but the analysis doesn't work with some tools:
- XMPP or other protocols that your interception proxy does not recognize
- mobile application development platforms like [Xamarin](https://www.xamarin.com/platform "Xamarin"), which produces apps that don't use your Android or iOS phone's local proxy settings and you can't redirect the requests to your interception proxy
- push notification interception, with, for example, GCM/FCM on Android (see also "Firebase/Google Cloud Messaging [FCM/GCM]" in basic security testing on Android)

In such cases, we must first monitor and analyze the network traffic. When you don't have a rooted Android device and you need to get all network traffic, tools like ettercap can be good solutions. On iOS, you can create a "Remote Virtual Interface" instead; this is described in the chapter "Basic Security Testing" for iOS. 

> Any device and operating system can succumb to man-in-the-middle attacks because this kind of attack is executed on OSI Layer 2, through ARP Spoofing. When you're the MITM, you may not be able to see clear textual data because the data in transit may have been encrypted with TLS. It will, however, give you valuable information about the hosts involved, the protocols used, and the ports the app is communicating through.

#### Preparation

You can simulate a man-in-the-middle attack during network penetration testing by using [Ettercap](https://ettercap.github.io/ettercap/ "Ettercap") for [ARP poisoning or spoofing](https://en.wikipedia.org/wiki/ARP_spoofing "ARP poisoning/spoofing") to the target machines. When such an attack is successful, all packets transmitted between two given machines are redirected to a third machine that acts as the man-in-the-middle and can intercept the traffic for analysis.

Intercept all network traffic for a full dynamic analysis of a mobile app. Consider several preparatory steps to intercept messages.

**Ettercap Installation**

Ettercap is available through the package managers of all major Unix-like operating systems. You need to install it on the machine that will act as the MITM. It can be installed with brew on macOS.

```bash
$ brew install ettercap
```

Ettercap can be installed with `apt-get` on Debian-based Linux distributions.

```bash
sudo apt-get install zlib1g zlib1g-dev
sudo apt-get install build-essential
sudo apt-get install ettercap
```

**Network Analyzer Tool**

Install a tool that allows you to monitor and analyze the network traffic that will be redirected to your machine. The two most common network monitoring (or capturing) tools are

- [Wireshark](https://www.wireshark.org "Wireshark") (CLI pendant: [tshark](https://www.wireshark.org/docs/man-pages/tshark.html "TShark")) and
- [tcpdump](http://www.tcpdump.org/tcpdump_man.html "tcpdump").

Wireshark offers a GUI and is more straightforward for those who aren't used to the command line. If you're looking for a command line tool, you should use either TShark or tcpdump. All of these tools are available through the package managers of all major Unix-like operating systems.

**Network Setup**

To get into a man-in-the-middle position, your machine should be connected to the wireless network that the mobile phone and its gateway are connected to. Once connected, you need the following information:

- the mobile phone's IP address
- the gateway's IP address

#### Man-in-the-middle Attack

Start ettercap with the following command, replacing the first IP address with the wireless network gateway and the second with your mobile device's IP address.

```bash
$ sudo ettercap -T -i en0 -M arp:remote /192.168.0.1// /192.168.0.105//
```

Start the mobile phone's browser and navigate to example.com. You should see output like

```bash
ettercap 0.8.2 copyright 2001-2015 Ettercap Development Team

Listening on:
   en0 -> AC:BC:32:81:45:05
	  192.168.0.105/255.255.255.0
	  fe80::c2a:e80c:5108:f4d3/64

SSL dissection needs a valid 'redir_command_on' script in the etter.conf file
Privileges dropped to EUID 65534 EGID 65534...

  33 plugins
  42 protocol dissectors
  57 ports monitored
20388 mac vendor fingerprint
1766 tcp OS fingerprint
2182 known services

Scanning for merged targets (2 hosts)...

* |==================================================>| 100.00 %

2 hosts added to the hosts list...

ARP poisoning victims:

 GROUP 1 : 192.168.0.1 F8:E9:03:C7:D5:10

 GROUP 2 : 192.168.0.102 20:82:C0:DE:8F:09
Starting Unified sniffing...

Text only Interface activated...
Hit 'h' for inline help

Sun Jul  9 22:23:05 2017 [855399]
  :::0 --> ff02::1:ff11:998b:0 | SFR (0)


Sun Jul  9 22:23:10 2017 [736653]
TCP  172.217.26.78:443 --> 192.168.0.102:34127 | R (0)

Sun Jul  9 22:23:10 2017 [737483]
TCP  74.125.68.95:443 --> 192.168.0.102:35354 | R (0)
```

If you see similar output, you can also see all the mobile phone's network traffic. This includes DNS, DHCP, and any other form of communication, so the output can be quite "noisy." You should therefore know how to focus on relevant traffic with [DisplayFilters in Wireshark](https://wiki.wireshark.org/DisplayFilters "DisplayFilters") or [how to filter with tcpdump](https://danielmiessler.com/study/tcpdump/#gs.OVQjKbk "A tcpdump Tutorial and Primer with Examples").

As an example, we will redirect all requests from a Xamarin app to our interception proxy in the next section.

#### Xamarin

Xamarin is a mobile application development platform that can produce [native Android](https://developer.xamarin.com/guides/android/getting_started/ "Getting Started with Android") and [iOS apps](https://developer.xamarin.com/guides/ios/ "Getting Started with iOS") with Visual Studio and C#.

When you're testing a Xamarin app and trying to set the system proxy Wi-Fi settings, you won't be able to see any HTTP requests in your interception proxy because the apps Xamarin creates don't use your phone's local proxy settings. There are two ways to resolve this:

1. Add a [default proxy to the app](https://developer.xamarin.com/api/type/System.Net.WebProxy/ "System.Net.WebProxy Class") by adding the following code to the `OnCreate` or `Main` method and re-creating the app:

```
WebRequest.DefaultWebProxy = new WebProxy("192.168.11.1", 8080);
```

2. --TODO What about Inspeckage to set a proxy within the app? https://github.com/ac-pm/Inspeckage

3. Use ettercap to get into a MITM position (see the previous section). When you're the MITM, you only need to redirect port 443 to your interception proxy, which runs on localhost. This can be done on macOS with the command `rdr`:

```bash
$ echo "
rdr pass inet proto tcp from any to any port 443 -> 127.0.0.1 port 8080
" | sudo pfctl -ef -
```

The interception proxy needs to listen to the port specified in the port forwarding rule above (port 8080).

**CA Certificates**

If the CA certificates aren't already installed, install them to your mobile device. This will allow you to intercept HTTPS requests:

- [Install your interception proxy's CA certificate to your Android phone](https://support.portswigger.net/customer/portal/articles/1841102-installing-burp-s-ca-certificate-in-an-android-device "Installing Burp's CA Certificate in an Android Device").
- [Install your interception proxy's CA certificate to your iOS phone](https://support.portswigger.net/customer/portal/articles/1841108-configuring-an-ios-device-to-work-with-burp "Configuring an iOS Device to Work With Burp")

**Intercepting Traffic**

Use the app's functions. You should see HTTP messages in your interception proxy.

> When using ettercap, you need to activate "Support invisible proxying" in Proxy Tab / Options / Edit Interface

#### Span Port/Port Forwarding

As an alternative to a MITM attack with ettercap, you can use a Wi-Fi Access Point (AP) or router. The setup requires access to the AP configuration, which should be clarified prior to the engagement. If reconfiguration is possible, you should first determine whether the AP either:
- supports port forwarding or
- has a span or mirror port.

In both scenarios, you must configure the AP so that it points to your machine's IP address. You can then use tools like Wireshark to monitor and record the traffic for further investigation.
