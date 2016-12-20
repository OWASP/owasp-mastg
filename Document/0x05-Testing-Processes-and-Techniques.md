# Testing Processes and Techniques

## Black-box Testing


## White-box Testing


## Static Analysis


## Dynamic Analysis

### Runtime Analysis
(.. TODO ..)

### Traffic Analysis

Dynamic analysis of the traffic exchanged between client and server can be performed by launching a Man-in-the-middle (MITM) attack. This can be achieved by using an interception proxy like Burp Suite (Professional) or OWASP ZAP for HTTP traffic.  

* [Configuring an Android Device to work with Burp](https://support.portswigger.net/customer/portal/articles/1841101-configuring-an-android-device-to-work-with-burp)
* [Configuring an iOS Device to work with Burp](https://support.portswigger.net/customer/portal/articles/1841108-configuring-an-ios-device-to-work-with-burp)

In case another (proprietary) protocol is used in a mobile App that is not HTTP, the following tools can be used to try to intercept or analyze the traffic: 
* [Mallory](https://github.com/intrepidusgroup/mallory)
* [Wireshark](https://www.wireshark.org/)
