---
hide: toc
title: MASTG Demos
---

??? info "About the MASTG Demos"

    Demos are write-ups that demonstrate the weakness in a sample application. They can be seen as a practical application of the tests.

    Each demo contains the following information:

    - **Overview**: A brief description of the demo.
    - **Sample**: A code snippet that demonstrates the weakness.
    - **Steps**: The specific steps followed to identify the weakness in the sample code.
    - **Observation**: A description of the results of running the test against the code.
    - **Evaluation**: The evaluation of the results of the test explaining why it failed or passed.

    All demos in the MASTG are written in markdown and are located in the `demos` directory.

    Each demo directory contains the following files:

    - `MASTG-DEMO-****.md`: The markdown file containing the demo write-up.
    - `MastgTest.kt`: The Kotlin code snippet that demonstrates the weakness.
    - `output.txt`: The output of running the test against the code.
    - `run.sh`: The script that runs the test against the code.

    Depending on the test, the demo may contain additional files, such as configuration files or additional code snippets, scripts (e.g. in Python), or output files. The samples are written in Kotlin or Swift, depending on the platform. In some cases, the samples will also include configuration files such as `AndroidManifest.xml` or `Info.plist`.

    If the sample can be decompiled, the decompiled code is also provided in the demo. This is useful for understanding the code in the context of the application.

    Demos are required to be fully self-contained and should not rely on external resources or dependencies. This ensures that the demos can be run independently and that the results are reproducible. They must be proven to work on the provided sample applications and must be tested thoroughly before being included in the MASTG.

    **MAS Test Apps**

    In order for our new demos to be reliable and consistent, we needed to make sure that the results were reproducible and could be tested and validated. This is where the new MASTestApps came in. They are two very simple apps that mirror each other on Android and iOS. Demos must be implemented using these apps. This helps the reviewer and serves as a playground to create and practice your MAS skills.

    - [MASTestApp-Android](https://github.com/cpholguera/MASTestApp-Android)
    - [MASTestApp-iOS](https://github.com/cpholguera/MASTestApp-iOS)

    Simply clone the repository and follow the instructions to run the apps on your local machine. Use them to validate the demos before submitting them to the MASTG.

??? warning "IMPORTANT DISCLAIMER"

    Please read this disclaimer carefully as it contains essential information regarding the use of the Mobile Application Security Testing Guide (MASTG).

    - **Scope and Purpose of MASTG Artifacts**: Each new release of the MASTG will include a collection of testing resources such as Static Application Security Testing (SAST) rules, Dynamic Application Security Testing (DAST) scripts, and other relevant artifacts. However, it's crucial to understand that these resources are not intended to provide a comprehensive solution for all your security testing needs.

    - **Baseline**: The resources provided in the MASTG serve as a baseline or starting point. They are designed to be used as references and learning tools in the field of mobile application security. While they offer valuable insights and guidelines, they should be used as a foundation upon which you can build and tailor your own specific automation and security testing processes.

    - **No Guarantee of Complete Coverage**: The OWASP Mobile Application Security (MAS) project, the entity behind the MASTG, explicitly does not assume responsibility or guarantee that the provided code and resources will identify all possible vulnerabilities in mobile applications. Security testing is a complex and evolving field, and the effectiveness of any set of tools or rules varies depending on numerous factors, including the specific context of the application being tested, the experience of the tester, and the changing landscape of security threats.

    - **Potential for False Positives and Negatives**: Users of the MASTG should be aware that the testing resources might generate a significant number of false positives (incorrectly identifying non-issues as vulnerabilities) and false negatives (failing to detect actual vulnerabilities). It is essential to approach the results with a critical and informed mindset, and supplement automated testing with manual review and analysis.

    - **Continuous Learning and Adaptation**: The field of mobile application security is continuously evolving. As such, the MASTG resources should be seen as a living body of knowledge, subject to updates and improvements. Users are encouraged to stay informed about the latest security trends and techniques and to actively contribute to the evolution of these resources.

    By using the MASTG, you acknowledge and agree to these limitations. It's recommended to combine the use of MASTG resources with other security practices and tools to achieve a more comprehensive and effective security testing strategy for your mobile applications.
