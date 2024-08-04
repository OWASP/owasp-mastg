---
hide: toc
title: Testing Tools
---

??? info "About the MASTG Tools"

    The OWASP MASTG includes many tools to assist you in executing test cases, allowing you to perform static analysis, dynamic analysis, network interception, etc. These tools are intended to help you perform your own assessments, rather than provide a conclusive result on the security status of an app. It's important to review the output of these tools carefully, as it can contain both false positives and false negatives.

    The goal of the MASTG is to be as accessible as possible. For this reason, we prioritize including tools that meet the following criteria:

    - Open-source
    - Free to use
    - Capable of analyzing recent Android/iOS applications
    - Regularly updated
    - Strong community support

    In instances where no suitable open-source alternative exists, we may include closed-source tools. However, any closed-source tools included must be free to use, as we aim to avoid featuring paid tools whenever possible. This also extends to freeware or community editions of commercial tools.

    Our goal is to be vendor-neutral and to serve as a trusted learning resource, which is why we've **avoid the inclusion of "automated mobile application security scanners"** due to the competitive challenges they pose. Instead, we focus on tools that provide full code access and comprehensive testing, as they are better suited for educational purposes. Tools that lack this transparency, even if they offer a free version, typically do not meet the OWASP MAS project's inclusion criteria.

!!! warning "Important Disclaimer"

    These tools have been tested to work when added, but compatibility may vary depending on your OS version, the device you're testing, or whether you're using a rooted or jailbroken device. Tool functionality may also be affected by specific versions of the rooting/jailbreaking method or the tool itself. OWASP MASTG does not guarantee the functionality of the tools. If you encounter problems, try to search for solutions online or contact the tool owner (e.g. via GitHub Issues).
