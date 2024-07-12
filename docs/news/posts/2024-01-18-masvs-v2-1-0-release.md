---
title: "MASVS v2.1.0 Release & MASVS-PRIVACY"
date: 2024-01-18
authors: [carlos, sven]
---

We are thrilled to announce the release of the new version of the [OWASP Mobile Application Security Verification Standard (MASVS) v2.1.0](https://github.com/OWASP/owasp-masvs/releases/tag/v2.1.0) including the new MASVS-PRIVACY category and CycloneDX support.

<!-- more -->

### MASVS-PRIVACY

After collecting and processing all feedback from the [MASVS-PRIVACY Proposal](https://docs.google.com/document/d/1jq7V9cRureRFF_XT7d_Z9H_SLsaFs43cE50k6zMRu0Q/edit?usp=sharing) we're releasing the [new MASVS-PRIVACY category](https://mas.owasp.org/MASVS/12-MASVS-PRIVACY/).

<center>
<img style="width: 80%; border-radius: 5px" src="/assets/news/masvs_privacy.png"/>
</center>

> The main goal of MASVS-PRIVACY is to provide a **baseline for user privacy**. It is not intended to cover all aspects of user privacy, especially when other standards and regulations such as ENISA or the GDPR already do that. We focus on the app itself, looking at what can be tested using information that's publicly available or found within the app through methods like static or dynamic analysis.
>
> While some associated tests can be automated, others necessitate manual intervention due to the nuanced nature of privacy. For example, if an app collects data that it didn't mention in the app store or its privacy policy, it takes careful manual checking to spot this.

The new controls are:

- **MASVS-PRIVACY-1**: The app minimizes access to sensitive data and resources.
- **MASVS-PRIVACY-2**: The app prevents identification of the user.
- **MASVS-PRIVACY-3**: The app is transparent about data collection and usage.
- **MASVS-PRIVACY-4**: The app offers user control over their data.

### CycloneDX Support

The MASVS is now available in CycloneDX format (OWASP_MASVS.cdx.json), a widely adopted standard for software bill of materials (SBOM). This format enables easier integration and automation within DevOps pipelines, improving visibility and management of mobile app security. By using CycloneDX, developers and security teams can more efficiently assess, track and comply with MASVS requirements, resulting in more secure mobile applications.
