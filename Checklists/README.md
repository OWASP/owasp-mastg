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
| Mobile_App_Security_Checklist-English_1.1.3.1.xlsx | 91960753cf03cf6c4b254d0f0285f369fe55d85c5200caed4cbcdf714d572cb7 |
| Mobile_App_Security_Checklist-French_1.1.3.1.xlsx | 8d5be09ec00505751bebb4c9d415835e1f7ab0b02ed684c202cc3c0a09b5813f |
| Mobile_App_Security_Checklist-Japanese_1.1.3.1.xlsx | 2175db9c11812d48b21c7a4a2c5294ff2481b9fa3dba75b56122bfe1f365a288 |
| Mobile_App_Security_Checklist-Korean_1.1.3.1.xlsx | ae02b09103e9b4c1dfbd570ca7675bf0d1c7570569bf3d9a8ee2750530932946 |
| Mobile_App_Security_Checklist-Spanish_1.1.3.1.xlsx | eb349132fb853b006d1dc1da455aa9bd984fcd0cdef7ba489b451edd81e57874 |

### Generate on Linux

```bash
$ sha256sum Mobile_App_Security_Checklist-*
91960753cf03cf6c4b254d0f0285f369fe55d85c5200caed4cbcdf714d572cb7 *Mobile_App_Security_Checklist-English_1.1.3.1.xlsx
8d5be09ec00505751bebb4c9d415835e1f7ab0b02ed684c202cc3c0a09b5813f *Mobile_App_Security_Checklist-French_1.1.3.1.xlsx
2175db9c11812d48b21c7a4a2c5294ff2481b9fa3dba75b56122bfe1f365a288 *Mobile_App_Security_Checklist-Japanese_1.1.3.1.xlsx
ae02b09103e9b4c1dfbd570ca7675bf0d1c7570569bf3d9a8ee2750530932946 *Mobile_App_Security_Checklist-Korean_1.1.3.1.xlsx
eb349132fb853b006d1dc1da455aa9bd984fcd0cdef7ba489b451edd81e57874 *Mobile_App_Security_Checklist-Spanish_1.1.3.1.xlsx
```

### Generate on Windows

```powershell
owasp-mstg\Checklists> Get-FileHash -Algorithm SHA256 -Path .\Mobile_App_Security_Checklist-* | fl


Algorithm : SHA256
Hash      : 91960753CF03CF6C4B254D0F0285F369FE55D85C5200CAED4CBCDF714D572CB7
Path      : C:\Users\elie.saad\Github\owasp-mstg\Checklists\Mobile_App_Security_Checklist-English_1.1.3.1.xlsx

Algorithm : SHA256
Hash      : 8D5BE09EC00505751BEBB4C9D415835E1F7AB0B02ED684C202CC3C0A09B5813F
Path      : C:\Users\elie.saad\Github\owasp-mstg\Checklists\Mobile_App_Security_Checklist-French_1.1.3.1.xlsx

Algorithm : SHA256
Hash      : 2175DB9C11812D48B21C7A4A2C5294FF2481B9FA3DBA75B56122BFE1F365A288
Path      : C:\Users\elie.saad\Github\owasp-mstg\Checklists\Mobile_App_Security_Checklist-Japanese_1.1.3.1.xlsx

Algorithm : SHA256
Hash      : AE02B09103E9B4C1DFBD570CA7675BF0D1C7570569BF3D9A8EE2750530932946
Path      : C:\Users\elie.saad\Github\owasp-mstg\Checklists\Mobile_App_Security_Checklist-Korean_1.1.3.1.xlsx

Algorithm : SHA256
Hash      : EB349132FB853B006D1DC1DA455AA9BD984FCD0CDEF7BA489B451EDD81E57874
Path      : C:\Users\elie.saad\Github\owasp-mstg\Checklists\Mobile_App_Security_Checklist-Spanish_1.1.3.1.xlsx
```

### Generate on MacOS

```bash
owasp-mstg/Checklists> shasum -a 256 Mobile_App_Security_Checklist-*
91960753cf03cf6c4b254d0f0285f369fe55d85c5200caed4cbcdf714d572cb7  Mobile_App_Security_Checklist-English_1.1.3.1.xlsx
8d5be09ec00505751bebb4c9d415835e1f7ab0b02ed684c202cc3c0a09b5813f  Mobile_App_Security_Checklist-French_1.1.3.1.xlsx
2175db9c11812d48b21c7a4a2c5294ff2481b9fa3dba75b56122bfe1f365a288  Mobile_App_Security_Checklist-Japanese_1.1.3.1.xlsx
ae02b09103e9b4c1dfbd570ca7675bf0d1c7570569bf3d9a8ee2750530932946  Mobile_App_Security_Checklist-Korean_1.1.3.1.xlsx
eb349132fb853b006d1dc1da455aa9bd984fcd0cdef7ba489b451edd81e57874  Mobile_App_Security_Checklist-Spanish_1.1.3.1.xlsx
```
