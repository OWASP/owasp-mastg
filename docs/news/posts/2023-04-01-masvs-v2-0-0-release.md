---
title: "MASVS v2.0.0 Release"
date: 2023-04-01
authors: [carlos, sven]
---

We are thrilled to announce the release of the new version of the [OWASP Mobile Application Security Verification Standard (MASVS) v2.0.0](https://github.com/OWASP/owasp-masvs/releases/tag/v2.0.0). With this update, we have set out to achieve several key objectives to ensure that MASVS remains a leading industry standard for mobile application security.

<!-- more -->

- **Keep Abstraction**: we have worked hard to maintain the level of abstraction that has made MASVS so valuable in the past. We leave the details to the MASTG.
- **Simplify**: we have simplified the MASVS by removing redundancies and overlaps in the security controls. This will make it easier for users to understand the standard and implement it effectively in their own projects.
- **Bring Clarity**: we have worked hard to use standard terminology wherever possible, drawing on established sources such as NIST-SP 800-175B and NIST OSCAL, as well as well-known and used sources such as CWEs, Android Developer Docs, and Apple Docs.
- **Narrow Scope**: we have narrowed the scope of MASVS to rely more heavily on other industry standards such as the OWASP ASVS, OWASP SAMM and NIST.SP.800-218 SSDF v1.1. This will ensure that MASVS remains relevant and up-to-date in a rapidly evolving landscape of mobile application security.

We believe that these changes will make the OWASP MASVS v2.0.0 an even more valuable resource for developers and security practitioners alike, and we are excited to see how the industry embraces these updates.

The MASVS v2.0.0 was presented at the OWASP AppSec Dublin 2023, you can watch the presentation [▶️ here](https://www.youtube.com/watch?v=GxcabVcCEiQ).

### Why are there no levels in the new MASVS controls?

The Levels you already know (L1, L2 and R) will be fully reviewed and backed up with a corrected and well-documented threat model.

**Enter MAS Profiles:** We are moving the levels to the MASTG tests so that we can evaluate different situations for the same control (e.g., in MASVS-STORAGE-1, it's OK to store data unencrypted in app internal storage for L1, but L2 requires data encryption). This can lead to different tests depending on the security profile of the application.

### Transition Phase

The MASTG, in its current version v1.5.0, currently still supports the MASVS v1.5.0. Bringing the MASTG to v2.0.0 to be fully compatible with MASVS v2.0.0 will take some time. That's why we need to introduce a "transition phase". We're currently mapping all new proposed test cases to the new profiles (at least L1 and L2), so even if the MASTG refactoring is not complete, you'll know what to test for, and you'll be able to find most of the tests already in the MASTG.

- Map the current MASTG tests to the new MASVS v2.0.0.
- Assign profiles to the proposed MASTG atomic tests (at least L1, L2 and R).

### Special Thanks

We thank everyone that has participated in the MASVS Refactoring. You can access all Discussion and documents for the refactoring [here](https://github.com/OWASP/owasp-masvs/discussions/categories/big-masvs-refactoring).

You'll notice that we have one **new author in the MASVS: Jeroen Beckers**

> Jeroen is a mobile security lead responsible for quality assurance on mobile security projects and for R&D on all things mobile. Ever since his master's thesis on Android security, Jeroen has been interested in mobile devices and their (in)security. He loves sharing his knowledge with other people, as is demonstrated by his many talks & trainings at colleges, universities, clients and conferences.

💙 Special thanks to our [MAS Advocate](https://mas.owasp.org/MASTG/Intro/0x02c-Acknowledgements/#mas-advocates), [NowSecure](https://www.nowsecure.com/), who has once again demonstrated their commitment to the project by continuously supporting it with time/dedicated resources as well as feedback, data and content contributions.

<center>
<img style="width: 40%; border-radius: 5px" src="https://user-images.githubusercontent.com/29175115/229281279-d739fa75-b3da-467d-91a0-82be88c688bf.png"/>
</center>
