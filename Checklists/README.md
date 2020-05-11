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
| Mobile_App_Security_Checklist-English_1.1.3.1.xlsx | ff030f7fbff9aade234aaa8a078352d3d8154ceda3899d77e6b8ed335f77f4dd |
| Mobile_App_Security_Checklist-French_1.1.3.1.xlsx | 17ac6d18ad791bcb045e36d165ab1592f11c20c2157fd618eda16356072928c4 |
| Mobile_App_Security_Checklist-Japanese_1.1.3.1.xlsx | 1be6c12ad72894d3b19dce404485170c3ebbe4081fcaae74ae26d01009021794 |
| Mobile_App_Security_Checklist-Korean_1.1.3.1.xlsx | 7b83bd510c7710c608a521fc99937f90765b0615c06be02b2365fb52e134332a |
| Mobile_App_Security_Checklist-Spanish_1.1.3.1.xlsx | 9f84210e19e9c8db58d82800020ef814e212bfa95cef59b50f4b50239b66454e |

### Generate on Linux

```bash
$ sha256sum Mobile_App_Security_Checklist-*
ff030f7fbff9aade234aaa8a078352d3d8154ceda3899d77e6b8ed335f77f4dd *Mobile_App_Security_Checklist-English_1.1.3.1.xlsx
17ac6d18ad791bcb045e36d165ab1592f11c20c2157fd618eda16356072928c4 *Mobile_App_Security_Checklist-French_1.1.3.1.xlsx
1be6c12ad72894d3b19dce404485170c3ebbe4081fcaae74ae26d01009021794 *Mobile_App_Security_Checklist-Japanese_1.1.3.1.xlsx
7b83bd510c7710c608a521fc99937f90765b0615c06be02b2365fb52e134332a *Mobile_App_Security_Checklist-Korean_1.1.3.1.xlsx
9f84210e19e9c8db58d82800020ef814e212bfa95cef59b50f4b50239b66454e *Mobile_App_Security_Checklist-Spanish_1.1.3.1.xlsx
```

### Generate on Windows

```powershell
owasp-mstg\Checklists> Get-FileHash -Algorithm SHA256 -Path .\Mobile_App_Security_Checklist-* | fl


Algorithm : SHA256
Hash      : FF030F7FBFF9AADE234AAA8A078352D3D8154CEDA3899D77E6B8ED335F77F4DD
Path      : C:\Users\user\Github\owasp-mstg\Checklists\Mobile_App_Security_Checklist-English_1.1.3.1.xlsx

Algorithm : SHA256
Hash      : 17AC6D18AD791BCB045E36D165AB1592F11C20C2157FD618EDA16356072928C4
Path      : C:\Users\user\Github\owasp-mstg\Checklists\Mobile_App_Security_Checklist-French_1.1.3.1.xlsx

Algorithm : SHA256
Hash      : 1BE6C12AD72894D3B19DCE404485170C3EBBE4081FCAAE74AE26D01009021794
Path      : C:\Users\user\Github\owasp-mstg\Checklists\Mobile_App_Security_Checklist-Japanese_1.1.3.1.xlsx

Algorithm : SHA256
Hash      : 7B83BD510C7710C608A521FC99937F90765B0615C06BE02B2365FB52E134332A
Path      : C:\Users\user\Github\owasp-mstg\Checklists\Mobile_App_Security_Checklist-Korean_1.1.3.1.xlsx

Algorithm : SHA256
Hash      : 9F84210E19E9C8DB58D82800020EF814E212BFA95CEF59B50F4B50239B66454E
Path      : C:\Users\user\Github\owasp-mstg\Checklists\Mobile_App_Security_Checklist-Spanish_1.1.3.1.xlsx
```

### Generate on MacOS

```bash
owasp-mstg/Checklists> shasum -a 256 Mobile_App_Security_Checklist-*
ff030f7fbff9aade234aaa8a078352d3d8154ceda3899d77e6b8ed335f77f4dd  Mobile_App_Security_Checklist-English_1.1.3.1.xlsx
17ac6d18ad791bcb045e36d165ab1592f11c20c2157fd618eda16356072928c4  Mobile_App_Security_Checklist-French_1.1.3.1.xlsx
1be6c12ad72894d3b19dce404485170c3ebbe4081fcaae74ae26d01009021794  Mobile_App_Security_Checklist-Japanese_1.1.3.1.xlsx
7b83bd510c7710c608a521fc99937f90765b0615c06be02b2365fb52e134332a  Mobile_App_Security_Checklist-Korean_1.1.3.1.xlsx
9f84210e19e9c8db58d82800020ef814e212bfa95cef59b50f4b50239b66454e  Mobile_App_Security_Checklist-Spanish_1.1.3.1.xlsx
```
