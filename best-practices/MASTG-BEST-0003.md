---
title: Comply with Privacy Regulations and Best Practices
alias: comply-with-privacy-regulations
id: MASTG-BEST-0003
platform: android
---


Recommendations from [CWE-359](https://cwe.mitre.org/data/definitions/359.html).

## Phase: Requirements

Identify and consult all relevant regulations for personal privacy. An organization may be required to comply with certain federal and state regulations, depending on its location, the type of business it conducts, and the nature of any private data it handles. Regulations may include Safe Harbor Privacy Framework [REF-340], Gramm-Leach Bliley Act (GLBA) [REF-341], Health Insurance Portability and Accountability Act (HIPAA) [REF-342], General Data Protection Regulation (GDPR) [REF-1047], California Consumer Privacy Act (CCPA) [REF-1048], and others.

## Phase: Architecture and Design

Carefully evaluate how secure design may interfere with privacy, and vice versa. Security and privacy concerns often seem to compete with each other.

- From a security perspective, all important operations should be recorded so that any anomalous activity can later be identified.
- However, when private data is involved, this practice can in fact create risk. Although there are many ways in which private data can be handled unsafely, a common risk stems from misplaced trust.

Programmers often trust the operating environment in which a program runs, and therefore believe that it is acceptable store private information on the file system, in the registry, or in other locally-controlled resources. However, even if access to certain resources is restricted, this does not guarantee that the individuals who do have access can be trusted.

## References

- [REF-340] U.S. Department of Commerce. "Safe Harbor Privacy Framework". <https://web.archive.org/web/20010223203241/http://www.export.gov/safeharbor/>. URL validated: 2023-04-07.
- [REF-341] Federal Trade Commission. "Financial Privacy: The Gramm-Leach Bliley Act (GLBA)". <https://www.ftc.gov/business-guidance/privacy-security/gramm-leach-bliley-act>. URL validated: 2023-04-07.
- [REF-342] U.S. Department of Human Services. "Health Insurance Portability and Accountability Act (HIPAA)". <https://www.hhs.gov/hipaa/index.html>. URL validated: 2023-04-07.
- [REF-1047] Wikipedia. "General Data Protection Regulation". <https://en.wikipedia.org/wiki/General_Data_Protection_Regulation>.
- [REF-1048] State of California Department of Justice, Office of the Attorney General. "California Consumer Privacy Act (CCPA)". <https://oag.ca.gov/privacy/ccpa>.
