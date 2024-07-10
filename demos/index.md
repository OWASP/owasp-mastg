---
hide: toc
title: MASTG Demos
status: new
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
