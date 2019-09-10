<a href="https://leanpub.com/mobile-security-testing-guide"><img width=180px align="right" style="float: right;" src="../Document/Images/mstg-cover-release-small.jpg"></a>

# OWASP Mobile Security Testing Guide [![Twitter Follow](https://img.shields.io/twitter/follow/OWASP_MSTG.svg?style=social&label=Follow)](https://twitter.com/OWASP_MSTG)

[![Creative Commons License](https://licensebuttons.net/l/by-sa/4.0/88x31.png)](https://creativecommons.org/licenses/by-sa/4.0/ "CC BY-SA 4.0")

[![OWASP Flagship](https://img.shields.io/badge/owasp-flagship%20project-48A646.svg)](https://www.owasp.org/index.php/Category:OWASP_Project#tab=Project_Inventory)
[![Build Status](https://travis-ci.com/OWASP/owasp-mstg.svg?branch=master)](https://travis-ci.com/OWASP/owasp-mstg)

The checklists contained in the excel files allow a mapping between a given version of the [OWASP Mobile Security Testing Guide (MSTG)](https://github.com/OWASP/owasp-mstg "MSTG") and the [OWASP Mobile Application Verification Standard (MASVS)](https://github.com/OWASP/owasp-masvs "MASVS").

The MSTG version element (Dashboard - row 13) in the excel file represent the version of mstg which the links in the excel file will lead to.

Note that due to the continuous updating and restructuring of the MSTG, the links of different versions are not all identical. And changing the mstg version (Dashboard - row 13) may break the links in the excel file.

Newer and older versions of the Excel are released on a regular basis and can be found at [the release page](https://github.com/OWASP/owasp-mstg/releases "Releases").

## Files Hash

You should ensure that the generated hash is similar to the one in the table below! File hashes serve as a file verification mechanism to ensure that you are using the same excel found in this guide, and that it was downloaded properly.

| Filename | SHA256 Sum |
|---|---|
| Mobile_App_Security_Checklist-English_1.1.2.xlsx | 9f0118a3149c5fe0e495440897be8ccbf4e546f5b52518ef54a3f403015b284e |
| Mobile_App_Security_Checklist-French_1.1.2.xlsx | 4ac489734a009f1101aab37cd96925b067e19baead9e4b395a7048ad026844b5 |
| Mobile_App_Security_Checklist-Japanese_1.1.2.xlsx | a5c636fba4119305197bfa7bc38dbb15b704f3437312f9481896984b16160542 |
| Mobile_App_Security_Checklist-Spanish_1.1.xlsx | f561377a9e45e235af0db9bcf483577e55c4cfd5a40a42ea6a9335681add9ccc |

### Generate on Linux

```bash
$ sha256sum Mobile_App_Security_Checklist-*
9f0118a3149c5fe0e495440897be8ccbf4e546f5b52518ef54a3f403015b284e *Mobile_App_Security_Checklist-English_1.1.2.xlsx
4ac489734a009f1101aab37cd96925b067e19baead9e4b395a7048ad026844b5 *Mobile_App_Security_Checklist-French_1.1.2.xlsx
a5c636fba4119305197bfa7bc38dbb15b704f3437312f9481896984b16160542 *Mobile_App_Security_Checklist-Japanese_1.1.2.xlsx
f561377a9e45e235af0db9bcf483577e55c4cfd5a40a42ea6a9335681add9ccc *Mobile_App_Security_Checklist-Spanish_1.1.xlsx
```

### Generate on Windows

```powershell
owasp-mstg\Checklists> Get-FileHash -Algorithm SHA256 -Path .\Mobile_App_Security_Checklist-* | fl


Algorithm : SHA256
Hash      : 9F0118A3149C5FE0E495440897BE8CCBF4E546F5B52518EF54A3F403015B284E
Path      : C:\Users\elie.saad\Github\owasp-mstg\Checklists\Mobile_App_Security_Checklist-English_1.1.2.xlsx

Algorithm : SHA256
Hash      : 4AC489734A009F1101AAB37CD96925B067E19BAEAD9E4B395A7048AD026844B5
Path      : C:\Users\elie.saad\Github\owasp-mstg\Checklists\Mobile_App_Security_Checklist-French_1.1.2.xlsx

Algorithm : SHA256
Hash      : A5C636FBA4119305197BFA7BC38DBB15B704F3437312F9481896984B16160542
Path      : C:\Users\elie.saad\Github\owasp-mstg\Checklists\Mobile_App_Security_Checklist-Japanese_1.1.2.xlsx

Algorithm : SHA256
Hash      : F561377A9E45E235AF0DB9BCF483577E55C4CFD5A40A42EA6A9335681ADD9CCC
Path      : C:\Users\elie.saad\Github\owasp-mstg\Checklists\Mobile_App_Security_Checklist-Spanish_1.1.xlsx
```

### Generate on MacOS

```bash
owasp-mstg/Checklists> shasum -a 256 Mobile_App_Security_Checklist-*
9f0118a3149c5fe0e495440897be8ccbf4e546f5b52518ef54a3f403015b284e  Mobile_App_Security_Checklist-English_1.1.2.xlsx
4ac489734a009f1101aab37cd96925b067e19baead9e4b395a7048ad026844b5  Mobile_App_Security_Checklist-French_1.1.2.xlsx
a5c636fba4119305197bfa7bc38dbb15b704f3437312f9481896984b16160542  Mobile_App_Security_Checklist-Japanese_1.1.2.xlsx
f561377a9e45e235af0db9bcf483577e55c4cfd5a40a42ea6a9335681add9ccc  Mobile_App_Security_Checklist-Spanish_1.1.xlsx
```
