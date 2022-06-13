# Frontispiece

![OWASP MSTG](Images/OWASP_logo.png) \

## About the OWASP Mobile Security Testing Guide

The OWASP Mobile Security Testing Guide (MSTG) is a comprehensive manual for testing the security of mobile apps. It describes processes and techniques for verifying the requirements listed in the [Mobile Application Security Verification Standard (MASVS)](https://github.com/OWASP/owasp-masvs), and provides a baseline for complete and consistent security tests.

OWASP thanks the many authors, reviewers, and editors for their hard work in developing this guide. If you have any comments or suggestions on the Mobile Security Testing Guide, please join the discussion around MASVS and MSTG in the [OWASP Mobile Security Project Slack Channel](https://owasp.slack.com/messages/project-mobile_omtg/details/ "OWASP Mobile Security Project Slack Channel"). You can sign up for the Slack channel yourself using [this URL](https://owasp.slack.com/join/shared_invite/zt-g398htpy-AZ40HOM1WUOZguJKbblqkw# "Slack channel sign up").

> Please open an issue in our Github Repo if the invite has expired.

## OWASP MASVS and MSTG Adoption

The OWASP MASVS and MSTG are trusted by the following platform providers, standardization, governmental and educational institutions and companies.

### Mobile Platform Providers

<table>
<tr>
<td width="600px">

#### Google Android

Since 2021 Google has shown their support for the OWASP Mobile Security project (MSTG/MASVS) and has started providing continuous and high value feedback to the MASVS refactoring process via the [App Defense Alliance (ADA)](https://appdefensealliance.dev/) and its [MASA (Mobile Application Security Assessment) program](https://appdefensealliance.dev/masa).

With MASA, Google has acknowledged the importance of leveraging a globally recognized standard for mobile app security to the mobile app ecosystem. Developers can work directly with an Authorized Lab partner to initiate a security assessment. Google will recognize developers who have had their applications independently validated against a set of MASVS Level 1 requirements and will showcase this on their Data safety section.

We thank Google, the ADA and all its members for their support and for their excellent work on protecting the mobile app ecosystem.

</td>
<td width="400px" valign="top">
<img width="400px" src="Document/Images/Other/android-logo.png"/>
</td>

</tr>
</table>

### Standardization Institutions

<table>
<tr>

<td width="600px">

#### NIST (National Institute of Standards and Technology, United States)

The [National Institute of Standards and Technology (NIST)](https://www.nist.gov/about-nist) was founded in 1901 and is now part of the U.S. Department of Commerce. NIST is one of the nation's oldest physical science laboratories. Congress established the agency to remove a major challenge to U.S. industrial competitiveness at the time — a second-rate measurement infrastructure that lagged behind the capabilities of the United Kingdom, Germany and other economic rivals.

- [NIST.SP.800-163 "Vetting the Security of Mobile Applications" Revision 1, 2019](https://csrc.nist.gov/news/2019/nist-publishes-sp-800-163-rev-1 "National Institute of Standards and Technology")
- [NIST.SP.800-218 "Secure Software Development Framework (SSDF) v1.1: Recommendations for Mitigating the Risk of Software Vulnerabilities" v1.1, 2022](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-218.pdf)

</td>
<td width="400px" valign="top">
<img width="300px" src="Document/Images/Other/nist-logo.png"/>
</td>

</tr>
<tr>

<td width="600px">

#### BSI (Bundesamt für Sicherheit in der Informationstechnik, Germany)

BSI stands for "Federal Office for Information Security", it has the goal to promote IT security in Germany and is the central IT security service provider for the federal government.

- [Technical Guideline BSI TR-03161 Security requirements for eHealth applications v1.0, 2020](https://www.bsi.bund.de/SharedDocs/Downloads/EN/BSI/Publications/TechGuidelines/TR03161/TR-03161.pdf)
- [Prüfvorschrift für den Produktgutachter des „ePA-Frontend des Versicherten“ und des „E-Rezept-Frontend des Versicherten v2.0, 2021](https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/DigitaleGesellschaft/Pruefvorschrift_Produktgutachter_ePA-Frontend.pdf)

</td>
<td width="400px" valign="top">
<img width="300px" src="Document/Images/Other/bsi-logo.png"/>
</td>

</tr>
<tr>

<td width="600px">

#### ioXt

The mission of the [ioXt Alliance](https://www.ioxtalliance.org/) is to build confidence in Internet of Things products through multi-stakeholder, international, harmonized, and standardized security and privacy requirements, product compliance programs, and public transparency of those requirements and programs.

In 2021, ioXt has [extended its security principles through the Mobile Application profile](https://www.ioxtalliance.org/news-events-blog/ioxt-alliance-expands-certification-program-for-mobile-and-vpn-security), so that app developers can ensure their products are built with, and maintain, high cybersecurity standards such as the OWASP MASVS and the VPN Trust Initiative. The ioXt Mobile Application profile is a security standard that applies to any cloud connected mobile app and provides the much needed market transparency for consumer and commercial mobile app security.

- [ioXt Base Profile v2.0](https://static1.squarespace.com/static/5c6dbac1f8135a29c7fbb621/t/6078677c7d7b84799f1eaa5b/1618503553847/ioXt_Base_Profile.pdf)

</td>
<td width="400px" valign="top">
<img width="300px" src="Document/Images/Other/ioxt-logo.png"/>
</td>

</tr>
</table>

### Governmental Institutions

| Name | Document | Year |
| --- | -------------------- | - |
| European Payments Council | [Payment Threats and Fraud Trends Report](https://www.europeanpaymentscouncil.eu/sites/default/files/kb/file/2021-12/EPC193-21%20v1.0%202021%20Payments%20Threats%20and%20Fraud%20Trends%20Report.pdf) | 2021 |
| European Payments Council | [Mobile Initiated SEPA Credit Transfer Interoperability Implementation Guidelines, including SCT Instant (MSCT IIGs)](https://www.europeanpaymentscouncil.eu/document-library/guidance-documents/mobile-initiated-sepa-instant-credit-transfer-interoperability) | 2019 |
| ENISA (European Union Agency for Cybersecurity) | [Good Practices for Security of SMART CARS](https://www.enisa.europa.eu/publications/smart-cars) | 2019 |
| Government of India, Ministry of Electronics & Information Technology | [Adoption of Mobile AppSec Verification Standard (MASVS) Version 1.0 of OWASP](http://egovstandards.gov.in/sites/default/files/Adoption%20of%20Mobile%20AppSec%20Verification%20Standard%20%28MASVS%29%20Version%201.0%20of%20OWASP_0.pdf) | 2019 |
| Finish Transport and Communication Agency (TRAFICOM) | [Assessment guideline for electronic identification services (Draft)](https://www.traficom.fi/sites/default/files/media/file/DRAFT%20Traficom%20guideline%20211%202019%20conformity%20assessment%20of%20eID%20service.pdf) | 2019 |
| Gobierno de España INCIBE | [Ciberseguridad en Smart Toys](https://www.incibe.es/sites/default/files/contenidos/guias/doc/guia_smarttoys_final.pdf) | 2019 |

### Educational Institutions

| Name | Document | Year |
| --- | -------------------- | - |
| University of Florida, Florida Institute for Cybersecurity Research, United States | ["SO{U}RCERER : Developer-Driven Security Testing Framework for Android Apps"](https://arxiv.org/pdf/2111.01631.pdf) | 2021 |
| University of Adelaide, Australia and Queen Mary University of London, United Kingdom | [An Empirical Assessment of Global COVID-19 Contact Tracing Applications](https://arxiv.org/pdf/2006.10933.pdf) | 2021 |
| School of Information Technology, Mapúa University, Philippines | [A Vulnerability Assessment on the Parental Control Mobile Applications Security: Status based on the OWASP Security Requirements](http://www.ieomsociety.org/singapore2021/papers/1104.pdf) | 2021 |

### Companies

**Note: the quality of the application of the MASVS/MSTG by these companies has not been vetted by the MSTG team. It is just an indicator of adoption reported publicly.**

- [7asecurity](https://7asecurity.com "7asecurity")
- [Brewsec](https://brewsec.io/ "Brewsec")
- [Briskinfosec Technology and Consulting Pvt Ltd](https://www.briskinfosec.com/ "Briskinfosec Technology and Consulting Pvt Ltd")
- [Citadelo](https://citadelo.com/en/blog/how-to-order-a-pen-test/ "Citadelo")
- [Comsec](https://comsecglobal.com/ "Comsec")
- [continuumsecurity](https://continuumsecurity.net "continuumsecurity")
- [Cyber Ninjas](https://www.CyberNinjas.com "Cyber Ninjas")
- [ESCRYPT GmbH](https://www.escrypt.com "ESCRYPT GmbH")
- [FH Münster - University of applied sciences](https://www.fh-muenster.de "FH Münster - University of applied sciences")
- [Genexus](https://www.genexus.com "Genexus") & [Genexus Consulting](https://www.genexusconsulting.com/es/ "Genexus Consulting")
- [Hackenproof](https://hackenproof.com "Hackenproof")
- [Infosec](https://Infosec.com.br "Infosec")
- [Netguru](https://www.netguru.co/ "Netguru")
- [NowSecure](https://www.nowsecure.com/ "NowSecure")
- [NVISO](https://www.nviso.eu "NVISO")
- [Randorisec](https://randorisec.fr/ "Randorisec")
- [Secarma](https://www.secarma.com/ "Secarma")
- [SecuRing](https://securing.biz/ "SecuRing")
- [Stingray Technologies](https://stingray-mobile.ru/  "Stingray Technologies")
- [STM Solutions](https://stmsolutions.pl/ "STM Solutions")
- [Toreon](https://www.toreon.com/ "Toreon")
- [VantagePoint](https://www.vantagepoint.sg "VantagePoint")
- [Vertical Structure](https://www.verticalstructure.com "Vertical Structure Ltd")
- [Websec Canada](https://www.websec.ca/mobile-application-security "Websec Canada")
- [Xebia](https://xebia.com "Xebia")

### Application in scientific research

- [STAMBA: Security Testing for Android Mobile Banking Apps](https://link.springer.com/chapter/10.1007/978-3-319-28658-7_57 "Advances in Signal Processing and Intelligent Recognition Systems pp 671-683")

### Books

- [Hands-On Security in DevOps](https://books.google.co.uk/books?id=bO1mDwAAQBAJ&pg=PA40&lpg=PA40&dq=owasp+mobile+security+testing+guide&source=bl&ots=pHhAasVgeC&sig=ACfU3U0yodcqH0O8Sjx3ADTN2m1tbHeCsg&hl=nl&sa=X&ved=2ahUKEwio2umM8tbiAhXgVBUIHehnAEU4UBDoATAIegQICRAB#v=onepage&q=owasp%20mobile%20security%20testing%20guide&f=false "Hands-On Security in DevOps in Google books")

### Call for Adopters

Are you actively using the MASVS or MSTG and want to be listed here? File an [issue on GitHub](https://github.com/OWASP/owasp-mstg/issues/new "New Issue"), contact Sven Schleier (Slack: *Sven*) or Carlos Holguera (Slack: *Carlos*), or send an email to [Sven](mailto:sven.schleier@owasp.org) or [Carlos](mailto:carlos.holguera@owasp.org).

## Disclaimer

Please consult the laws in your country before executing any tests against mobile apps by utilizing the MSTG materials. Refrain from violating the laws with anything described in the MSTG.

Our [Code of Conduct](https://github.com/OWASP/owasp-mstg/blob/master/CODE_OF_CONDUCT.md) has further details.

## Copyright and License

Copyright © The OWASP Foundation. This work is licensed under a [Creative Commons Attribution-ShareAlike 4.0 International License](https://creativecommons.org/licenses/by-sa/4.0/ "Creative Commons Attribution-ShareAlike 4.0 International License"). For any reuse or distribution, you must make clear to others the license terms of this work.

![OWASP MSTG](Images/CC-license.png) \

## ISBN

Our ISBN Number is 978-1-257-96636-3 and a hard copy of the MSTG can be ordered at [lulu.com](https://www.lulu.com/search?adult_audience_rating=00&page=1&pageSize=10&q=mobile+security+testing+guide).

## Acknowledgments

**Note**: This contributor table is generated based on our [GitHub contribution statistics](https://github.com/OWASP/owasp-mstg/graphs/contributors "GitHub contribution statistics"). For more information on these stats, see the [GitHub Repository README](https://github.com/OWASP/owasp-mstg/blob/master/README.md "GitHub Repository README"). We manually update the table, so be patient if you're not listed immediately.

### Authors

#### Bernhard Mueller

Bernhard is a cyber security specialist with a talent for hacking systems of all kinds. During more than a decade in the industry, he has published many zero-day exploits for software such as MS SQL Server, Adobe Flash Player, IBM Director, Cisco VOIP, and ModSecurity. If you can name it, he has probably broken it at least once. BlackHat USA commended his pioneering work in mobile security with a Pwnie Award for Best Research.

#### Sven Schleier

Sven is an experienced web and mobile penetration tester and assessed everything from historic Flash applications to progressive mobile apps. He is also a security engineer that supported many projects end-to-end during the SDLC to "build security in". He was speaking at local and international meetups and conferences and is conducting hands-on workshops about web application and mobile app security.

#### Jeroen Willemsen

Jeroen is a principal security architect with a passion for mobile security and risk management. He has supported companies as a security coach, a security engineer and as a full-stack developer, which makes him a jack of all trades. He loves explaining technical subjects: from security issues to programming challenges.

#### Carlos Holguera

Carlos is a mobile security research engineer who has gained many years of hands-on experience in the field of security testing for mobile apps and embedded systems such as automotive control units and IoT devices. He is passionate about reverse engineering and dynamic instrumentation of mobile apps and is continuously learning and sharing his knowledge.

### Co-Authors

Co-authors have consistently contributed quality content and have at least 2,000 additions logged in the GitHub repository.

#### Romuald Szkudlarek

Romuald is a passionate cyber security & privacy professional with over 15 years of experience in the web, mobile, IoT and cloud domains. During his career, he has been dedicating his spare time to a variety of projects with the goal of advancing the sectors of software and security. He is teaching regularly at various institutions. He holds CISSP, CCSP, CSSLP, and CEH credentials.

#### Jeroen Beckers

Jeroen is a mobile security lead responsible for quality assurance on mobile security projects and for R&D on all things mobile. Although he started his career as a programmer, he found that it was more fun to take things apart than to put things together, and the switch to security was quickly made. Ever since his master's thesis on Android security, Jeroen has been interested in mobile devices and their (in)security. He loves sharing his knowledge with other people, as is demonstrated by his many talks & trainings at colleges, universities, clients and conferences.

#### Vikas Gupta

Vikas is an experienced cyber security researcher, with expertise in mobile security. In his career he has worked to secure applications for various industries including fintech, banks and governments. He enjoys reverse engineering, especially obfuscated native code and cryptography. He holds masters in security and mobile computing, and an OSCP certification. He is always open to share his knowledge and exchange ideas.

### Top Contributors

Top contributors have consistently contributed quality content and have at least 500 additions logged in the GitHub repository.

- Pawel Rzepa
- Francesco Stillavato
- Henry Hoggard
- Andreas Happe
- Kyle Benac
- Paulino Calderon
- Alexander Anthuk
- Caleb Kinney
- Abderrahmane Aftahi
- Koki Takeyama
- Wen Bin Kong
- Abdessamad Temmar
- Cláudio André
- Slawomir Kosowski
- Bolot Kerimbaev
- Lukasz Wierzbicki

<br/>
<br/>

### Contributors

Contributors have contributed quality content and have at least 50 additions logged in the GitHub repository. Their Github handle is listed below:

kryptoknight13, DarioI, luander, oguzhantopgul, Osipion, mpishu, pmilosev, isher-ux, thec00n, ssecteam, jay0301, magicansk, jinkunong, nick-epson, caitlinandrews, dharshin, raulsiles, righettod, karolpiateknet, mkaraoz, Sjord, bugwrangler, jasondoyle, joscandreu, yog3shsharma, ryantzj, rylyade1, shivsahni, diamonddocumentation, 51j0, AnnaSzk, hlhodges, legik, abjurato, serek8, mhelwig, locpv-ibl and ThunderSon.

### Mini Contributors

Many other contributors have committed small amounts of content, such as a single word or sentence (less than 50 additions). Their Github handle is listed below:

jonasw234, zehuanli, jadeboer, Isopach, prabhant, jhscheer, meetinthemiddle-be, bet4it, aslamanver, juan-dambra, OWASP-Seoul, hduarte, TommyJ1994, forced-request, D00gs, vasconcedu, mehradn7, whoot, LucasParsy, DotDotSlashRepo, enovella, ionis111, vishalsodani, chame1eon, allRiceOnMe, crazykid95, Ralireza, Chan9390, tamariz-boop, abhaynayar, camgaertner, EhsanMashhadi, fujiokayu, decidedlygray, Ali-Yazdani, Fi5t, MatthiasGabriel, colman-mbuya and anyashka.

### Reviewers

Reviewers have consistently provided useful feedback through GitHub issues and pull request comments.

- Jeroen Beckers
- Sjoerd Langkemper
- Anant Shrivastava

### Editors

- Heaven Hodges
- Caitlin Andrews
- Nick Epson
- Anita Diamond
- Anna Szkudlarek

### Donators

While both the MASVS and the MSTG are created and maintained by the community on a voluntary basis, sometimes a little bit of outside help is required. We therefore thank our donators for providing the funds to be able to hire technical editors. Note that their donation does not influence the content of the MASVS or MSTG in any way. The Donation Packages are described on the [OWASP Project Wiki](https://www.owasp.org/index.php/OWASP_Mobile_Security_Testing_Guide#tab=Sponsorship_Packages "OWASP Mobile Security Testing Guide Donation Packages").

![OWASP MSTG](Images/Donators/donators.png) \

### Older Versions

The Mobile Security Testing Guide was initiated by Milan Singh Thakur in 2015. The original document was hosted on Google Drive. Guide development was moved to GitHub in October 2016.

#### OWASP MSTG "Beta 2" (Google Doc)

| Authors | Reviewers | Top Contributors |
| --- | --- | --- |
| Milan Singh Thakur, Abhinav Sejpal, Blessen Thomas, Dennis Titze, Davide Cioccia, Pragati Singh, Mohammad Hamed Dadpour, David Fern, Ali Yazdani, Mirza Ali, Rahil Parikh, Anant Shrivastava, Stephen Corbiaux, Ryan Dewhurst, Anto Joseph, Bao Lee, Shiv Patel, Nutan Kumar Panda, Julian Schütte, Stephanie Vanroelen, Bernard Wagner, Gerhard Wagner, Javier Dominguez | Andrew Muller, Jonathan Carter, Stephanie Vanroelen, Milan Singh Thakur  | Jim Manico, Paco Hope, Pragati Singh, Yair Amit, Amin Lalji, OWASP Mobile Team|

#### OWASP MSTG "Beta 1" (Google Doc)

| Authors | Reviewers | Top Contributors |
| --- | --- | --- |
| Milan Singh Thakur, Abhinav Sejpal, Pragati Singh, Mohammad Hamed Dadpour, David Fern, Mirza Ali, Rahil Parikh | Andrew Muller, Jonathan Carter | Jim Manico, Paco Hope, Yair Amit, Amin Lalji, OWASP Mobile Team  |
