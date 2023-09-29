---
hide:
  - toc
---

# OWASP MASVS

<img align="right" style="border-radius: 3px; margin: 3em; box-shadow: rgba(149, 157, 165, 0.2) 0px 8px 24px;" width="350px" src="../assets/masvs_cover.png">

<a href="https://github.com/OWASP/owasp-masvs/">:material-github: GitHub Repo</a>

The **OWASP MASVS (Mobile Application Security Verification Standard)** is the industry standard for mobile app security. It can be used by mobile software architects and developers seeking to develop secure mobile applications, as well as security testers to ensure completeness and consistency of test results.

<br>

<button class="mas-button" onclick="window.location.href='https://github.com/OWASP/owasp-masvs/releases/latest/download/OWASP_MASVS.pdf';"> Download the MASVS v2.0.0</button>

<br>

<span style="color: darkgray; font-size: small"> :material-translate: Starting with MASVS v2.0.0, translations will no longer be included to focus on the development of MASTG v2.0.0. We encourage the community to create and maintain their own translations. Thank you to all the past translators who generously volunteered their time and expertise to make the MASVS accessible to non-English speaking communities. We truly appreciate your contributions and hope to continue working together in the future. The past MASVS v1.5.0 translations are still [available in the MASVS repo](https://github.com/OWASP/owasp-masvs/releases/tag/v1.5.0).</span>

<br>

## The MASVS Control Groups

The standard is divided into various groups of security controls, labeled **MASVS-XXXXX**, that represent the most critical areas of the mobile attack surface:

- [**MASVS-STORAGE**](MASVS/05-MASVS-STORAGE.md): Secure storage of sensitive data on a device (data-at-rest).
- [**MASVS-CRYPTO**](MASVS/06-MASVS-CRYPTO.md): Cryptographic functionality used to protect sensitive data.
- [**MASVS-AUTH**](MASVS/07-MASVS-AUTH.md): Authentication and authorization mechanisms used by the mobile app.
- [**MASVS-NETWORK**](MASVS/08-MASVS-NETWORK.md): Secure network communication between the mobile app and remote endpoints (data-in-transit).
- [**MASVS-PLATFORM**](MASVS/09-MASVS-PLATFORM.md): Secure interaction with the underlying mobile platform and other installed apps.
- [**MASVS-CODE**](MASVS/10-MASVS-CODE.md): Security best practices for data processing and keeping the app up-to-date.
- [**MASVS-RESILIENCE**](MASVS/11-MASVS-RESILIENCE.md): Resilience to reverse engineering and tampering attempts.

To complement the MASVS, the OWASP MAS project also provides the [OWASP Mobile Application Security Testing Guide (MASTG)](/MASTG/) and the [OWASP MAS Checklist](/checklists/) which together are the perfect companion for verifying the controls listed in the OWASP MASVS and demonstrate compliance.

!!! warning "MAS Security Testing Profiles"
    **Starting on v2.0.0 the MASVS does not contain "verification levels"**. The MAS project has traditionally provided three verification levels (L1, L2 and R), which were revisited during the MASVS refactoring in 2023, and have been reworked as "security testing profiles" and moved over to the OWASP MASTG.
    <br><br>
    While we move things around and as a temporary measure, the [OWASP MAS Checklist](/checklists/) will still contain the old verification levels, associated with the current MASTG v1 tests. However, note that the levels will be completely reworked and reassigned to the corresponding MASTG tests in the next release.

<br><br>
