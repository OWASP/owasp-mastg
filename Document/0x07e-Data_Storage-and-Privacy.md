### Test Case Testing User Device Management

#### Overview
There are two forms of user device management:

- Managing your data and sessions accross devices given your application. This is where this section is about.
- Manage the actual device itself: how can an application influence the security state of the device and does it do this propperly according to best practices. 

The claims that prove ones identity (e.g. a JWT token) or the authorization (e.g. the access and refresh tokens) are the ones that often need the most attention if it comes to managing data. 



#### Static Analysis

#### Dynamic Analysis

#### Remediation


#### References

##### OWASP Mobile Top 10 2016
* M4 - Insecure Authentication - https://www.owasp.org/index.php/Mobile_Top_10_2016-M4-Insecure_Authentication

##### OWASP MASVS

* 4.9: "A second factor of authentication exists at the remote endpoint and the 2FA requirement is consistently enforced."
* 4.10: "Step-up authentication is required to enable actions that deal with sensitive data or transactions."

##### CWE
-- TODO [PROVIDE A DESCRIPTION ON USER DEVICE MANAGEMENT".] --
- CWE-287: Improper Authentication
- CWE-308: Use of Single-factor Authentication

##### Info

* [1] SOURCE  - URL