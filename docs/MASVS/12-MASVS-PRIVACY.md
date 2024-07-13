# MASVS-PRIVACY: Privacy

The main goal of MASVS-PRIVACY is to provide a **baseline for user privacy**. It is not intended to cover all aspects of user privacy, especially when other standards and regulations such as ENISA or the GDPR already do that. We focus on the app itself, looking at what can be tested using information that's publicly available or found within the app through methods like static or dynamic analysis.

While some associated tests can be automated, others necessitate manual intervention due to the nuanced nature of privacy. For example, if an app collects data that it didn't mention in the app store or its privacy policy, it takes careful manual checking to spot this.

> **Note on "Data Collection and Sharing"**:For the MASTG tests, we treat "Collect" and "Share" in a unified manner. This means that whether the app is sending data to another server or transferring it to another app on the device, we view it as data that's potentially leaving the user's control. Validating what happens to the data on remote endpoints is challenging and often not feasible due to access restrictions and the dynamic nature of server-side operations. Therefore, this issue is outside of the scope of the MASVS.

**IMPORTANT DISCLAIMER**:

MASVS-PRIVACY is not intended to serve as an exhaustive or exclusive reference. While it provides valuable guidance on app-centric privacy considerations, it should never replace comprehensive assessments, such as a Data Protection Impact Assessment (DPIA) mandated by the General Data Protection Regulation (GDPR) or other pertinent legal and regulatory frameworks. Stakeholders are strongly advised to undertake a holistic approach to privacy, integrating MASVS-PRIVACY insights with broader assessments to ensure comprehensive data protection compliance. Given the specialized nature of privacy regulations and the complexity of data protection, these assessments are best conducted by privacy experts rather than security experts.
