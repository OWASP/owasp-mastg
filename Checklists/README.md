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

```

```
| Filename | SHA256 Sum |
|---|---|
| Mobile_App_Security_Checklist-English_1.2.xlsx | 80027dca50a3be9f724c32f84117be6e961d62f2a4fa3eab5a94ac5c21ff06c8 |
| Mobile_App_Security_Checklist-French_1.2.xlsx | 080e281bdd2133f6f96da50380fbe500adf7009ed92f654699ebcab725c14609 |
| Mobile_App_Security_Checklist-Japanese_1.2.xlsx | d08108f7f4b998c6c39bfc75a7537b7e437fe282d556db715bb11b5bd922ab90 |
| Mobile_App_Security_Checklist-Korean_1.2.xlsx | 849d65307bd1046329b4019a09bdacf5ccf22a1226028eed1eab94fde293cfcc |
| Mobile_App_Security_Checklist-Spanish_1.2.xlsx | 4c530937706bbd946622bc806c0fe5fdbc604bd280e7546620eb5de9d1897bb6 |

### Generate on Linux / macOS

```bash
$ sha256sum *.xlsx
80027dca50a3be9f724c32f84117be6e961d62f2a4fa3eab5a94ac5c21ff06c8  Mobile_App_Security_Checklist-English_1.2.xlsx
080e281bdd2133f6f96da50380fbe500adf7009ed92f654699ebcab725c14609  Mobile_App_Security_Checklist-French_1.2.xlsx
d08108f7f4b998c6c39bfc75a7537b7e437fe282d556db715bb11b5bd922ab90  Mobile_App_Security_Checklist-Japanese_1.2.xlsx
849d65307bd1046329b4019a09bdacf5ccf22a1226028eed1eab94fde293cfcc  Mobile_App_Security_Checklist-Korean_1.2.xlsx
4c530937706bbd946622bc806c0fe5fdbc604bd280e7546620eb5de9d1897bb6  Mobile_App_Security_Checklist-Spanish_1.2.xlsx
```

### Generate on Windows

```powershell
owasp-mstg\Checklists> Get-FileHash -Algorithm SHA256 -Path .\Mobile_App_Security_Checklist-* | fl


Algorithm : SHA256
Hash      : 80027dca50a3be9f724c32f84117be6e961d62f2a4fa3eab5a94ac5c21ff06c8
Path      : C:\Users\user\Github\owasp-mstg\Checklists\Mobile_App_Security_Checklist-English_1.2.xlsx

Algorithm : SHA256
Hash      : 080e281bdd2133f6f96da50380fbe500adf7009ed92f654699ebcab725c14609
Path      : C:\Users\user\Github\owasp-mstg\Checklists\Mobile_App_Security_Checklist-French_1.2.xlsx

Algorithm : SHA256
Hash      : d08108f7f4b998c6c39bfc75a7537b7e437fe282d556db715bb11b5bd922ab90
Path      : C:\Users\user\Github\owasp-mstg\Checklists\Mobile_App_Security_Checklist-Japanese_1.2.xlsx

Algorithm : SHA256
Hash      : 849d65307bd1046329b4019a09bdacf5ccf22a1226028eed1eab94fde293cfcc
Path      : C:\Users\user\Github\owasp-mstg\Checklists\Mobile_App_Security_Checklist-Korean_1.2.xlsx

Algorithm : SHA256
Hash      : 4c530937706bbd946622bc806c0fe5fdbc604bd280e7546620eb5de9d1897bb6
Path      : C:\Users\user\Github\owasp-mstg\Checklists\Mobile_App_Security_Checklist-Spanish_1.2.xlsx
```
