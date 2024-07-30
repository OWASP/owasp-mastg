# Testing Tools

The OWASP MASTG includes many tools to assist you in executing test cases, allowing you to perform static analysis, dynamic analysis, dynamic instrumentation, etc. These tools are meant to help you conduct your own assessments, rather than provide a conclusive result on an application's security status. It's essential to carefully review the tools' output, as it can contain both false positives and false negatives.

The goal of the MASTG is to be as accessible as possible. For this reason, we prioritize including tools that meet the following criteria:

- Open-source
- Free to use
- Capable of analyzing recent Android/iOS applications
- Regularly updated
- Strong community support

In instances where no suitable open-source alternative exists, we may include closed-source tools. However, any closed-source tools included must be free to use, as we aim to avoid featuring paid tools whenever possible. This also extends to freeware or community editions of commercial tools.

Our goal is to be vendor-neutral and to serve as a trusted learning resource, so the specific category of "automated mobile application security scanners" presents a unique challenge. For this reason, we have historically avoided including such tools due to the competitive disadvantages they can create among vendors. In contrast, we prioritize tools like MobSF that provide full access to their code and a comprehensive set of tests, making them excellent for educational purposes. Tools that lack this level of transparency, even if they offer a free version, generally do not meet the inclusion criteria of the OWASP MAS project.

> Disclaimer: Each tool included in the MASTG examples was verified to be functional at the time it was added. However, the tools may not work properly depending on the OS version of both your host computer and your test device. The functionality of the tools can also be affected by whether you're using a rooted or jailbroken device, the specific version of the rooting or jailbreaking method, and/or the tool version itself. The OWASP MASTG does not assume any responsibility for the operational status of these tools. If you encounter a broken tool or example, we recommend searching online for a solution or contacting the tool's provider directly. If the tool has a GitHub page, you may also open an issue there.
