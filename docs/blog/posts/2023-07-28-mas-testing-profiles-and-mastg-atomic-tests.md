---
title: "MAS Testing Profiles and MASTG Atomic Tests"
date: 2023-07-28
authors: [carlos, sven]
---

The MASTG refactoring is a significant upgrade that addresses some existing challenges and introduces exciting new features. It aims to streamline compliance, simplify testing and improve usability for security testers and other stakeholders.

### MAS Testing Profiles

As part of the MASVS refactoring, we've replaced the three traditional verification levels (L1, L2, and R) with security testing profiles in the MASTG. These new profiles are designed to enhance our ability to capture various security nuances associated with mobile apps, allowing us to evaluate different situations for the same MASVS control. For instance, in [MASVS-STORAGE-1](https://mas.owasp.org/MASVS/controls/MASVS-STORAGE-1/), it's acceptable to store data unencrypted in app internal storage for MAS-L1, but MAS-L2 requires data encryption.

<!-- more -->

The [new MAS Testing Profiles](https://docs.google.com/document/d/1paz7dxKXHzAC9MN7Mnln1JiZwBNyg7Gs364AJ6KudEs/edit?usp=sharing) include revamped versions of the traditional levels and one new addition:

<center>
<img style="width: 60%; border-radius: 5px" src="/assets/news/mas_profiles.png"/>
</center>

Another interesting addition we're exploring for the near future is a 'Privacy' profile, which would focus on [tests that consider the privacy implications of various app features and functionalities](https://mas.owasp.org/MASTG/General/0x04i-Testing-User-Privacy-Protection/). We believe that this profile can become an essential tool in an era where privacy has become a significant concern.

> **HELP WANTED:** Today we're releasing the new MAS Testing Profiles and would love to hear what you think. Please [give your feedback here until the 31st of August 2023](https://docs.google.com/document/d/1paz7dxKXHzAC9MN7Mnln1JiZwBNyg7Gs364AJ6KudEs/edit?usp=sharing).

### Atomic Tests

One of the key changes in the MASTG refactoring is the introduction of the [new MASTG Atomic Tests](https://docs.google.com/spreadsheets/d/1Go5GpVvKJqTDxGbSLBPZb1hmYi5lXRc1D1AfrTTkUkY/edit?usp=sharing). The existing tests are currently quite large and often cover more than one MASVS control. With the introduction of Atomic Tests, we'll break these tests down into smaller, more manageable pieces. Our goal is to make these tests as self-contained and specific as possible to allow for reduced ambiguity, better understanding and easier execution. Each atomic test will have its unique ID for easy reference and traceability and will be mapped to the relevant controls from the MASVS.

<center>
<img style="width: 60%; border-radius: 5px" src="/assets/news/mastg_tests_refactoring.png"/>
</center>

But before we can start writing the new atomic tests, we need to finalize the proposal for the new MASTG Atomic Tests including mappings to the MASVS controls and the new MAS Testing profiles.

> **HELP WANTED:** Today we're releasing the new MASTG Atomic Tests Proposal and would love to hear what you think. Please [give your feedback here until the 31st of August 2023](https://docs.google.com/spreadsheets/d/1Go5GpVvKJqTDxGbSLBPZb1hmYi5lXRc1D1AfrTTkUkY/edit?usp=sharing).

### What's Next?

We are now in the process of transforming the MASTG, according to the changes highlighted above. We've already released the MASVS v2.0.0, and the rest of the year will be dedicated to the MASTG refactoring, which will involve creating hundreds of new tests. We believe these changes will significantly improve the usability and relevance of the MASTG. We're excited to keep you updated on our progress and look forward to your continued support and feedback.

> We would like to extend a special thanks to [our MAS Advocate NowSecure](https://mas.owasp.org/MASTG/Intro/0x02c-Acknowledgements/#our-mas-advocates). Their commitment to the OWASP project is not merely financial; it’s an investment of their most valuable resource – their people and their time. NowSecure has dedicated hours of expertise, extensive knowledge, and hard work towards making these changes a reality.
>
> Would you like to become a [MAS Advocate](https://mas.owasp.org/MASTG/Intro/0x02c-Acknowledgements/)? [Contact us](https://mas.owasp.org/contact/) to learn more.

A huge thanks goes of course to our wider community and all of our contributors. Your continuous participation and input have been instrumental in the evolution of the OWASP MAS project. It is through this collaborative effort that we can truly advance in the field of mobile app security. Thank you for being a part of this journey!
