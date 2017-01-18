## Android

### Most Common Attacks
--TODO : Cf OWASP Mobile Top 10 at https://www.owasp.org/index.php/Mobile_Top_10_2016-Top_10. Consider Permissions, Leakage from Logs and IPC Endpoint (In)Security --

### Android Security Mechanisms
-- TODO : for all, check if not duplicate with previous chapter!!! Sandbox (Dalvik / ART according to API level), IPC mechanism and Reference monitor, Binder, Discretionary - Mandatory Access Control / UID - GID / Filesystem, Applicative Architecture of an application : Permissions & Manifest, Application Signing. May be a part of Static / Dynamic Analysis chapter : each security mechanism efficiency can be checked at a given phase. --

### Setting Up Your Testing Environment
#### Hardware Considerations
##### Rooting your device
-- TODO : Which devices can be used : Nexus / Pixel --
-- TODO : Boot Process Description --
-- TODO : Boot Loaders and ROMs--

#### Software Considerations
-- TODO : Existing testing tools & tool suites : proxies, fuzzers, debuggers, vulnerability scanners, ... Most common tools : Binwalk, apktool, Dex2Jar, jad, Drozer, IDA --

### Attack Methodology
-- TODO : Cf testing methodologies from CEH, ... : map attack surface (Local and Remote) through Passive and Active Reconnaissance, Scanning, Gaining Access, Maintaining Access, Covering Tracks. As this is generic and common to iOS, may be part of the parent chapter --

### Static Analysis
-- TODO : Description, when it comes compared to dynamic analysis and why, what it can bring --
#### With Source Code ("White box")
-- TODO : Description of the methodology, pros and cons (what can be done / not done, related tools, vulnerabilities that can be found) --

#### Without Source Code ("Black box")
-- TODO : Description of the methodology, pros and cons (what can be done / not done, related tools, vulnerabilities that can be found) --

### Dynamic Analysis
-- TODO : Description, what it can bring --
