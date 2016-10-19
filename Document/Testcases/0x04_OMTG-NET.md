# Testing Network Communication

## Overview

[Describe what this chapter is about.]

## Test Cases

### OMTG-NET-004: Testing SSL Pinning
Certificate pinning allows to hard-code in the client the certificate that is known to be used by the server. This technique is used to reduce the threat of a rogue CA and CA compromise. Pinning the server’s certificate take the CA out of games. Mobile applications that implements certificate pinning only have to connect to a limited numbers of server, so a small list of trusted CA can be hard-coded in the application.

#### Detailed Guides

- [OMTG-NET-004 Android](0x04a_OMTG-NET_Android.md#OMTG-NET-004)
- [OMTG-NET-004 iOS](0x04b_OMTG-NET_iOS.md#OMTG-NET-004)

#### References

- OWASP MASVS : [Link to MASVS]
- CWE : [Link to CWE issue]

