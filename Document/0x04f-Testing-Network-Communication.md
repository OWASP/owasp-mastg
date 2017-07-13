## Testing Network Communication

The following chapter outlines network communication requirements of the MASVS into technical test cases. Test cases listed in this chapter are focused on server side and therefore are not relying on a specific implementation on iOS or Android.  

### Man-in-the-middle (MITM) attacks

Instead of a specific test case we will first talk about a generic attack pattern that is also applicable for mobile applications when executing a security test against them: man-in-the-middle (MITM) attacks.

Dynamic analysis by using an interception proxy can be straight forward if standard libraries are used in the app and all communication is done via HTTP. But there are several cases where this is no working:
- What if XMPP or other protocols are used that are not recognized by your interception proxy?
- What if mobile application development platforms like [Xamarin](https://www.xamarin.com/platform "Xamarin") are used, where the produced apps do not use the local proxy settings of your Android or iOS phone and you are not able to redirect the requests to your interception proxy?
- What if you want to intercept push notifications, like for example GCM/FCM on Android (see also "Firebase/Google Cloud Messaging (FCM/GCM)" in basic security testing on Android)?

In these cases we need to monitor and analyze the network traffic first in order to decide what to do next. When you don't have a rooted Android device and you need to get all network traffic, tools like ettercap can be a good solution to achieve this task. On iOS you can create a "Remote Virtual Interface" instead, which is described in the chapter "Basic Security Testing" for iOS. 

> Man-in-the-middle attacks work against any device and operating system as the attack is executed on OSI Layer 2 through ARP Spoofing. When you are MITM you might not be able to see clear text data, as the data in transit might be encrypted by using TLS, but it will give you valuable information about the hosts involved, the protocols used and the ports the app is communicating with.

#### Preparation

[Ettercap](https://ettercap.github.io/ettercap/ "Ettercap") can be used during network penetration tests in order to simulate a man-in-the-middle attack. This is achieved by executing [ARP poisoning or spoofing](https://en.wikipedia.org/wiki/ARP_spoofing "ARP poisoning/spoofing") to the target machines. When such an attack is successful, all packets between two machines are redirected to a third machine that acts as the man-in-the-middle and is able to intercept the traffic for analysis.

For a full dynamic analysis of a mobile app, all network traffic should be intercepted. To be able to intercept the messages several steps should be considered for preparation.

**Ettercap Installation**

Ettercap is available for all major Linux and Unix operating systems and should be part of their respective package installation mechanisms. You need to install it on your machine that will act as the MITM. On macOS it can be installed by using brew.

```bash
$ brew install ettercap
```

Ettercap can also be installed through `apt-get` on Debian based linux distributions.

```bash
sudo apt-get install zlib1g zlib1g-dev
sudo apt-get install build-essential
sudo apt-get install ettercap
```

**Network Analyzer Tool**

Install a tool that allows you to monitor and analyze the network traffic that will be redirected to your machine. The two most common network monitoring (or capturing) tools are:

- [Wireshark](https://www.wireshark.org "Wireshark") (CLI pendant: [tshark](https://www.wireshark.org/docs/man-pages/tshark.html "TShark")) and
- [tcpdump](http://www.tcpdump.org/tcpdump_man.html "tcpdump")

Wireshark offers a GUI and is more straightforward if you are not used to the command line. If you are looking for a command line tool you should either use TShark or tcpdump. All of these tools are available for all major Linux and Unix operating systems and should be part of their respective package installation mechanisms.

**Network Setup**

To be able to get a man-in-the-middle position your machine should be in the same wireless network as the mobile phone and the gateway it communicates to. Once this is done you need the following information:

- IP address of mobile phone
- IP address of gateway

#### Man-in-the-middle attack

Start ettercap with the following command and replace the first IP addresses with the network gateway in the wireless network and the second one with the one of your mobile device.

```bash
$ sudo ettercap -T -i en0 -M arp:remote /192.168.0.1// /192.168.0.105//
```

On the mobile phone start the browser and navigate to example.com, you should see output like the following:

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

If that's the case, you are now able to see the complete network traffic that is sent and received by the mobile phone. This includes also DNS, DHCP and any other form of communication and can therefore be quite "noisy". You should therefore know how to use [DisplayFilters in Wireshark](https://wiki.wireshark.org/DisplayFilters "DisplayFilters") or know [how to filter in tcpdump](https://danielmiessler.com/study/tcpdump/#gs.OVQjKbk "A tcpdump Tutorial and Primer with Examples") to focus only on the relevant traffic for you.

As an example we will now redirect all requests from a Xamarin app to our interception proxy in the next section.

#### Xamarin

Xamarin is a mobile application development platform that is capable of producing [native Android](https://developer.xamarin.com/guides/android/getting_started/ "Getting Started with Android") and [iOS apps](https://developer.xamarin.com/guides/ios/ "Getting Started with iOS") by using Visual Studio and C# as programming language.

When testing a Xamarin app and when you are trying to set the system proxy in the WiFi settings you won't be able to see any HTTP requests in your interception proxy, as the apps created by Xamarin do not use the local proxy settings of your phone. There are two ways to resolve this:

1. Add a [default proxy to the app](https://developer.xamarin.com/api/type/System.Net.WebProxy/ "System.Net.WebProxy Class"), by adding the following code in the `OnCreate()` or `Main()` method and re-create the app:

```
WebRequest.DefaultWebProxy = new WebProxy("192.168.11.1", 8080);
```

2. --TODO What about Inspeckage to set a proxy within the app? https://github.com/ac-pm/Inspeckage

3. Use ettercap in order to get a man-in-the-middle position (MITM), see the section above about how to setup a MITM attack. When being MITM we only need to redirect port 443 to our interception proxy running on localhost. This can be done by using the command `rdr` on macOS:

```bash
$ echo "
rdr pass inet proto tcp from any to any port 443 -> 127.0.0.1 port 8080
" | sudo pfctl -ef -
```

The interception proxy need to listen to the port specified in the port forwarding rule above, which is 8080

**CA Certificates**

If not already done, install the CA certificates in your mobile device which will allow us to intercept HTTPS requests:

- [Install the CA certificate of your interception proxy into your Android phone](https://support.portswigger.net/customer/portal/articles/1841102-installing-burp-s-ca-certificate-in-an-android-device "Installing Burp's CA Certificate in an Android Device").
- [Install the CA certificate of your interception proxy into your iOS phone](https://support.portswigger.net/customer/portal/articles/1841108-configuring-an-ios-device-to-work-with-burp "Configuring an iOS Device to Work With Burp")

**Intercepting Traffic**

Start using the app and trigger it's functions. You should see HTTP messages showing up in your interception proxy.

> When using ettercap you need to activate "Support invisible proxying" in Proxy Tab / Options / Edit Interface


#### Span Port / Port Forwarding

As an alternative to a MITM attack with ettercap, a Wifi Access Point (AP) or router can also be used instead. The setup requires access to the configuration of the AP and this should be clarified prior to the engagement. If it's possible to reconfigure you should check first if the AP supports either:
- port forwarding or
- has a span or mirror port.

In both scenarios the AP needs to be configured to point to your machines IP. Tools like Wireshark can then again be used to monitor and record the traffic for further investigation.


### Testing for Unencrypted Sensitive Data on the Network

#### Overview

One of the core functionalities of mobile apps is sending and/or receiving data from endpoints, over untrusted networks like the internet. It is possible for an attacker to sniff or even modify trough Man-in-the-middle (Mitm) attacks unencrypted information if he controls any part of the network infrastructure (e.g. an WiFi access point). This puts data in transit on risk and provides additional attack surface. For this reason, developers should make a general rule, that all communication should be [encrypted by using HTTPS](https://developer.android.com/training/articles/security-tips.html#Networking "Security Tips - Networking").

#### Static Analysis

Identify all external endpoints (backend APIs, third-party web services), the app communicates with and ensure that all those communication channels are encrypted. Look for HTTP or other URL schemas the app might be using.

#### Dynamic Analysis

The recommended approach is to intercept all network traffic coming to or from the tested application and check if it is encrypted. Network traffic can be intercepted using one of the following approaches:

- Capture all HTTP and Websocket traffic using an interception proxy, like [OWASP ZAP](https://security.secure.force.com/security/tools/webapp/zapandroidsetup "OWASP ZAP") or [Burp Suite Professional](https://support.portswigger.net/customer/portal/articles/1841101-configuring-an-android-device-to-work-with-burp "Configuring an Android device to work with Burp") and observe whether all requests are using HTTPS instead of HTTP.

Interception proxies like Burp or OWASP ZAP will only show HTTP traffic. There are however Burp plugins such as [Burp-non-HTTP-Extension](https://github.com/summitt/Burp-Non-HTTP-Extension) and [Mitm-relay](https://github.com/jrmdev/mitm_relay) that can be used to decode and visualize for example XMPP traffic and also other protocols.

> Please note, that some applications may not work with proxies like Burp or ZAP (because of Certificate Pinning). In such a scenario, please check "Testing Custom Certificate Stores and SSL Pinning" first. Also tools like Vproxy can be used to redirect all HTTP(S) traffic to your machine to sniff it and investigate for unencrypted requests.

- Capture all network traffic, using Tcpdump. This can be considered in case protocols are used that are not recognized by Burp or OWASP ZAP (e.g. XMPP). You can begin live capturing via the command:

```bash
adb shell "tcpdump -s 0 -w - | nc -l -p 1234"
adb forward tcp:1234 tcp:1234
```

You can display the captured traffic in a human-readable way by using Wireshark. It should be investigated what protocols are used and if they are unencrypted. It is important to capture all traffic (TCP and UDP), so you should run all possible functions of the tested application after starting intercepting it.

#### Remediation

Ensure that sensitive information is being sent via secure channels, using [HttpsURLConnection](https://developer.android.com/reference/javax/net/ssl/HttpsURLConnection.html "HttpsURLConnection"), or [SSLSocket](https://developer.android.com/reference/javax/net/ssl/SSLSocket.html "SSLSocket") for socket-level communication using TLS.

Please be aware that `SSLSocket` **does not** verify the hostname. The hostname verification should be done by using `getDefaultHostnameVerifier()` with expected hostname. A [code example](https://developer.android.com/training/articles/security-ssl.html#WarningsSslSocket "Warnings About Using SSLSocket Directly") can be found in the Android developer documentation.

#### References

##### OWASP Mobile Top 10 2016

- M3 - Insecure Communication - https://www.owasp.org/index.php/Mobile_Top_10_2016-M3-Insecure_Communication

##### OWASP MASVS

- V5.1: "Data is encrypted on the network using TLS. The secure channel is used consistently throughout the app."

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

Many mobile applications consume remote services over the HTTP protocol. HTTPS is HTTP over SSL/TLS. Other encrypted protocols are less common. Thus, it is important to ensure that the TLS configuration on server side is done properly. SSL is the older name of the TLS protocol and should no longer be used, since SSLv3 is considered vulnerable. TLS v1.2 and v1.3 are the modern and more secure versions, but many services still include configurations for TLS v1.0 and v1.1, to ensure compatibility with older clients.

In the situation where both the client and the server are controlled by the same organization and are used for the purpose of only communicating with each other, higher levels of security can be achieved by more [strict configurations](https://dev.ssllabs.com/projects/best-practices/ "Qualys SSL/TLS Deployment Best Practices").

If a mobile application connects to a specific server for a specific part of its functionality, the networking stack for that client can be tuned to ensure highest levels of security possible given the server configuration. Additionally, the mobile application may have to use a weaker configuration due to the lack of support in the underlying operating system.

For example, the popular Android networking library okhttp uses the following list as the preferred set of cipher suites, but these are only available on Android 7.0 and later:

- `TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256`
- `TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256`
- `TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384`
- `TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384`
- `TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256`
- `TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256`

To support earlier versions of Android, it adds a few ciphers that are not considered as secure as for example `TLS_RSA_WITH_3DES_EDE_CBC_SHA`.

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

In order to do a static analysis the configuration file need to be provided of the web server or reverse proxy where the HTTPS connection terminates. It is unusual to get this kind of information for a mobile penetration test and it also shouldn't be requested by you as the dynamic analysis is very fast and easy to execute.

In case you have the configuration file, check it against the [Qualys SSL/TLS Deployment Best Practices](https://dev.ssllabs.com/projects/best-practices/ "Qualys SSL/TLS Deployment Best Practices").

#### Dynamic Analysis

After identifying all servers your application is communicating with (e.g. by using an interception proxy) you should [verify if they allow the usage of weak ciphers, protocols or keys](https://www.owasp.org/index.php/Testing_for_Weak_SSL/TLS_Ciphers,_Insufficient_Transport_Layer_Protection_(OTG-CRYPST-001\) "Testing for Weak SSL/TLS Ciphers, Insufficient Transport Layer Protection (OTG-CRYPST-001)"). It can be done, using different tools:

- testssl.sh:

The GitHub repo of testssl.sh offers a compiled openssl version for download that supports **all cipher suites and protocols including SSLv2**.

```
$ ./testssl.sh --openssl bin/openssl.Linux.x86_64 yoursite.com
```

The tool will also help identifying potential misconfiguration or vulnerabilities by highlighting them in red. If you want to store the report preserving color and format use `aha`:

```
$ ./testssl.sh --openssl bin/openssl.Linux.x86_64 yoursite.com | aha > output.html
```

This will give you a HTML document that will match the  CLI output.

- O-Saft (OWASP SSL Advanced Forensic Tool):

There are [multiple options](https://www.owasp.org/index.php/O-Saft/Documentation#COMMANDS "O-Saft various tests") available for O-Saft, but the most general one is the following, verifying certificate, ciphers and SSL/TLS connection:

```
perl o-saft.pl +check www.example.com:443
```

O-Saft can also be run in GUI mode with the following command:

```
o-saft.tcl
```

#### Remediation

Any vulnerability or misconfiguration should be solved either by patching or reconfiguring the server. To properly configure transport layer protection for network communication, please follow the [OWASP Transport Layer Protection cheat sheet](https://www.owasp.org/index.php/Transport_Layer_Protection_Cheat_Sheet "Transport Layer Protection Cheat Sheet") and the [Qualys SSL/TLS Deployment Best Practices](https://dev.ssllabs.com/projects/best-practices/ "Qualys SSL/TLS Deployment Best Practices").

#### References

##### OWASP Mobile Top 10 2016

- M3 - Insecure Communication - https://www.owasp.org/index.php/Mobile_Top_10_2016-M3-Insecure_Communication

##### OWASP MASVS

- V5.2: "The TLS settings are in line with current best practices, or as close as possible if the mobile operating system does not support the recommended standards."

##### CWE

- CWE-327 - Use of a Broken or Risky Cryptographic Algorithm - https://cwe.mitre.org/data/definitions/327.html

##### Tools

- testssl.sh- https://testssl.sh
- O-Saft - https://www.owasp.org/index.php/O-Saft



### Verifying that Critical Operations Use Secure Communication Channels

#### Overview

For sensitive applications, like banking apps, [OWASP MASVS](https://github.com/OWASP/owasp-masvs/blob/master/Document/0x03-Using_the_MASVS.md "The Mobile Application Security Verification Standard") introduces "Defense in Depth" verification levels. Critical operations (e.g. user enrollment, or account recovery) of such sensitive applications are one of the most attractive targets from attacker's perspective. This creates a need of implementing advanced security controls for such operations, like adding additional channels (e.g. SMS and e-mail) to confirm user's action. Additional channels may reduce a risk of many attacking scenarios (mainly phishing), but only when they are out of any security faults.

#### Static Analysis

Review the code and identify those parts which refers to critical operations. Verify if it uses additional channels to perform such operation. Examples of additional verification channels are the following:

- Token (e.g. RSA token, yubikey)
- Push notification (e.g. Google Prompt)
- SMS
- E-mail
- Data from another website you had to visit or scan
- Data from a physical letter or physical entry point (e.g.: data you receive only after signing a document at the office of a bank)

#### Dynamic Analysis

Identify all critical operations implemented in the tested application (e.g. user enrollment, or account recovery, money transfer etc.). Ensure that each critical operation, requires at least one additional channel (e.g. SMS, e-mail, token etc.). Verify if the usage of these channels can be bypassed by directly calling the function.

#### Remediation

Ensure that critical operations require at least one additional channel to confirm user's action. Each channel must not be bypassed to execute a critical operation. If you are going to implement an additional factor to verify the user's identity, you may consider using [Infobip 2FA library](https://2-fa.github.io/libraries/android-library.html "Infobip 2FA library") or one-time passcodes (OTP) via [Google Authenticator](https://github.com/google/google-authenticator-android "Google Authenticator for Android").

#### References

##### OWASP Mobile Top 10 2016
- M3 - Insecure Communication - https://www.owasp.org/index.php/Mobile_Top_10_2016-M3-Insecure_Communication

##### OWASP MASVS
- V5.5: "The app doesn't rely on a single insecure communication channel (email or SMS) for critical operations, such as enrollments and account recovery."

##### CWE
- CWE-308 - Use of Single-factor Authentication
