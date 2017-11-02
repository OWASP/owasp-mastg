## Mobile App Security Testing

Before we dive into the technical details, we'll provide a brief overview of general security testing principles and key terminology. The concepts introduced are largely identical to those found in other types of penetration testing, so if you are an experienced tester you may want to skip this chapter.

Throughout the guide, we use "mobile app security testing" as a catchall phrase to refer to the evaluation of mobile app security via static and dynamic analysis. Terms such as "mobile app penetration testing" and "mobile app security review" are used somewhat inconsistently in the security industry, but these terms refer to roughly the same thing. A mobile app security test is usually part of a larger security assessment or penetration test that encompasses the client-server architecture and server-side APIs used by the mobile app.

In this guide, we cover mobile app security testing in two contexts. The first is the "classical" security test completed near the end of the development life cycle. In this context, the tester accesses a nearly finished or production-ready version of the app, identifies security issues, and writes a (usually devastating) report. The other context is characterized by the implementation of requirements and the automation of security tests from the beginning of the software development life cycle onwards. The same basic requirements and test cases apply to both contexts, but the high-level method and the level client interaction differ.

### Principles of Testing

#### White-box Testing versus Black-box Testing

Let's start by defining the concepts:
- Black-box testing is conducted without the tester's having any information about the app being tested. This process is sometimes called "zero-knowledge testing." The main purpose of this test is allowing the tester to behave like a real attacker in the sense of exploring possible uses for publicly available and discoverable information.
- White-box testing (sometimes called "full knowledge testing") is the total opposite of black-box testing in the sense that the tester has full knowledge of the app. The knowledge may encompass source code, documentation, and diagrams. Although much easier and faster than black-box testing, white-box testing doesn't allow for as many test cases. White-box testing is generally more useful for protecting the app against internal attackers.
- Gray-box testing is all testing that falls in between the two aforementioned testing types: some information is provided to the tester, and other information is intended to be discovered. This type of testing is an interesting compromise in the number of test cases, the cost, the speed, and the scope of testing. Gray-box testing is the most common kind of testing in the security industry.

We strongly advise that you request the source code so that you can use the testing time as efficiently as possible. The tester's code access obviously doesn't simulate an external attack, but it simplifies the identification of vulnerabilities by allowing the tester to verify every identified anomaly or suspicious behavior at the code level. A white-box test is the way to go if the app hasn't been tested before.

Even though decompiling on Android is straightforward, the source code may be obfuscated, and de-obfuscating will be time-consuming, possibly to the point of being even. Time constraints are therefore another reason for the tester to have access to the source code.

Clients may request black-box testing, but they should be told that external attackers don't operate within a limited time frame (like the tester). Therefore, black-box testing may be a good choice only if the app is already mature from a security point of view and the client wants to test the app's security controls.

#### Static versus Dynamic Analysis

Static analysis involves examining an application's components without executing them. It may be similar to white-box testing. The term often refers to manual or automatic source code analysis. 
OWASP provides information about [Static Code Analysis](https://www.owasp.org/index.php/Static_Code_Analysis "OWASP Static Code Analysis") that may help you understand techniques, strengths, weaknesses, and limitations.

Dynamic analysis involves examining the app from the outside while executing it. This type of analysis can be manual or automatic. It usually doesn't provide the information that static analysis provides, but it is a good way to detect interesting elements (assets, features, entry points, etc.) from a user's point of view. It may be similar to black-box testing.
OWASP provides information about [Dynamic Analysis](https://www.owasp.org/index.php/Dynamic_Analysis "OWASP Dynamic Analysis") that may help you understand how to analyze apps.

Now that we have defined static and dynamic analysis, let's dive deeper.

#### Vulnerability Analysis

Vulnerability analysis is usually the process of looking for vulnerabilities in an app. Although this may be done manually, automated scanners are usually used to identify the main vulnerabilities. Static and dynamic analysis are types of vulnerability analysis.

#### Static Analysis

During static analysis, the mobile app's source code is analyzed to ensure appropriate implementation of security controls. In most cases, a hybrid automatic/manual approach is used. Automatic scans catch the low-hanging fruit, and the human tester can explore the code base with specific usage contexts in mind.

##### Manual Code Analysis

A human reviewer performs manual code analysis by manually analyzing the mobile application's source code for security vulnerabilities. Methods range from a basic keyword search via the 'grep' command to a line-by-line examination of the source code. IDEs (Integrated Development Environments) often provide basic code review functions and can be extended with various tools.

A common approach to manual code analysis entails identifying key security vulnerability indicators by searching for certain APIs and keywords, such as database-related method calls like "executeStatement" or "executeQuery". Code containing these strings is a good starting point for manual analysis.

In contrast to automatic code analysis, manual code review is very good for identifying vulnerabilities in the business logic, standards violations, and design flaws, especially when the code is technically secure but logically flawed. Such scenarios are unlikely to be detected by any automatic code analysis tool.

A manual code review requires an expert code reviewer who is proficient in both the language and the frameworks used for the mobile application. Full code review can be a slow, tedious, time-consuming process for the reviewer, especially given large code bases with many dependencies.

##### Automatic Code Analysis

Automated analysis tools can be used to speed up the review process of Static Application Security Testing (SAST). They check the source code for compliance with a predefined set of rules or industry best practices, then typically display a list of findings or warnings and flags for all detected violations. Some static analysis tools run against the compiled app only, some must be fed the original source code, and some run as live-analysis plugins in the Integrated Development Environment (IDE).

Although some static code analysis tools incorporate a lot of information about the rules and semantics required to analyze mobile apps, they may produce many false positives, particularly if they are not configured for the target environment. A security professional must therefore always review the results.

The chapter "Testing tools" includes a list of static analysis tools.

#### Dynamic Analysis

The focus of dynamic analysis (also called DAST, or Dynamic Application Security Testing) is the testing and evaluation of apps via their real-time execution. The main objective of dynamic analysis is finding security vulnerabilities or weak spots in a program while it is running. Dynamic analysis is conducted both at the mobile platform layer and against the back-end services and APIs, where the mobile app's request and response patterns can be analyzed.

Dynamic analysis is usually used to check for security mechanisms that provide sufficient protection against the most prevalent types of attack, such as disclosure of data in transit, authentication and authorization issues, and server configuration errors.

##### Pros of Dynamic Analysis

Dynamic analysis must be combined with static analysis: it is not a silver bullet (e.g., you cannot find some flaws with dynamic analysis alone). The following are pros:

- Dynamic analysis doesn't require access to the source code and documentation.
- It can help you identify infrastructure, configuration, and patch issues that static analysis tools may miss.

##### Cons of Dynamic Analysis

The cons of dynamic analysis are:
- limited coverage (because identifying the test area requires the mobile application to be footprinted);
- lack of access to the instructions being executed (because the tool exercises the mobile application and matches requests and response patterns).


#### Avoiding False Positives

Automated testing tools' lack of sensitivity to app context is a challenge. These tools may identify a potential issue that's irrelevant. Such results are called "false positives."

For example, security testers commonly report vulnerabilities that are exploitable in a web browser but aren't relevant to the mobile app. This false positive occurs because automated tools used to scan the back-end service are based on regular browser-based web applications. Issues such as CSRF (Cross-site Request Forgery) and missing security headers are reported accordingly.

Let's take CSRF as an example. A successful CSRF attack requires the following:

- The ability to entice the logged-in user to open a malicious link in the web browser used to access the vulnerable site.
- The client (browser) must automatically add the session cookie or other authentication token to the request.

Mobile apps don't fulfill these requirements: even if Webviews and cookie-based session management are used, any malicious link the user clicks opens in the default browser, which has a separate cookie store.

Stored Cross-Site Scripting (CSS) can be an issue if the app includes Webviews, and it may even lead to command execution if the app exports JavaScript interfaces. However, reflected cross-site scripting is rarely an issue for the reason mentioned above (even though whether they should exist at all is arguable—escaping output is simply a best practice).

In any case, consider exploit scenarios when you perform the risk assessment; don't blindly trust your scanning tool's output.


#### Penetration Testing (a.k.a. Pentesting)

The classic approach involves all-around security testing of the app's final or near-final build, e.g., the build that's available at the end of the development process. For testing at the end of the development process, we recommend the [Mobile App Security Verification Standard (MASVS)](https://github.com/OWASP/owasp-masvs "OWASP MASVS") and the associated checklist. A typical security test is structured as follows:

- **Preparation** - defining the scope of security testing, including identifying applicable security controls, the organization's testing goals, and sensitive data. More generally, preparation includes all synchronization with the client as well as legally protecting the tester (who is often a third party). Remember, attacking a system without written authorization is illegal in many parts of the world!
- **Intelligence Gathering** - analyzing the **environmental** and **architectural** context of the app to gain a general contextual understanding.
- **Mapping the Application** - based on information from the previous phases; may be complemented by automated scanning and manually exploring the app. Mapping provides a thorough understanding of the app, its entry points, the data it holds, and the main potential vulnerabilities. These vulnerabilities can then be ranked according to the damage their exploitation would cause so that the security tester can prioritize them. This phase includes the creation of test cases that may be used during test execution.
- **Exploitation** - in this phase, the security tester tries to penetrate the app by exploiting the vulnerabilities identified during the previous phase. This phase is necessary for determining whether vulnerabilities are real (i.e., true positives).
- **Reporting** - in this phase, which is essential to the client, the security tester reports the vulnerabilities he or she has been able to exploit and documents the kind of compromise he or she has been able to perform, including the compromise's scope (for example, the data he or she has been able to access illegitimately). 

##### Preparation

The security level at which the app will be tested must be decided before testing. The security requirements should be decided at the beginning of the project. Different organizations have different security needs and resources available for investing in test activities. Although the controls in MASVS Level 1 (L1) are applicable to all mobile apps, walking through the entire checklist of L1 and Level 2 (L2) MASVS controls with technical and business stakeholders is a good way to decide on a level of test coverage.

Organizations may have different regulatory and legal obligations in certain territories. Even if an app doesn't handle sensitive data, some L2 requirements may be relevant (because of industry regulations or local laws). For example, two-factor authentication (2FA) may be obligatory for a financial app and enforced by a country's central bank and/or financial regulatory authorities.

Security goals/controls defined earlier in the development process may also be reviewed during the discussion with stakeholders. Some controls may conform to MASVS controls, but others may be specific to the organization or application.

![Preparation](Images/Chapters/0x03/mstg-preparation.png)

All involved parties must agree on the decisions and the scope in the checklist because these will define the baseline for all security testing.

###### Coordinating with the Client

Setting up a working test environment can be a challenging task. For example, restrictions on the enterprise wireless access points and networks may impede dynamic analysis performed at client premises. Company policies may prohibit the use of rooted phones or (hardware and software) network testing tools within enterprise networks. Apps that implement root detection and other reverse engineering countermeasures may significantly increase the work required for further analysis.

Security testing involves many invasive tasks, including monitoring and manipulating the mobile app's network traffic, inspecting the app data files, and instrumenting API calls. Security controls, such as certificate pinning and root detection, may impede these tasks and dramatically slow testing down.

To overcome these obstacles, you may want to request two of the app's build variants from the development team. One variant should be a release build so that you can determine whether the implemented controls are working properly and can be bypassed easily. The second variant should be a debug build for which certain security controls have been deactivated. Testing two different builds is the most efficient way to cover all test cases.

Depending on the scope of the engagement, this approach may not be possible. Requesting both production and debug builds for a white-box test will help you complete all test cases and clearly state the app's security maturity. The client may prefer that black-box tests be focused on the production app and the evaluation of its security controls' effectiveness.

The scope of both types of testing should be discussed during the preparation phase. For example, whether the security controls should be adjusted should be decided before testing. Additional topics are discussed below.

###### Identifying Sensitive Data

Classifications of sensitive information differ by industry and country. In addition, organizations may take a restrictive view of sensitive data, and they may have a data classification policy that clearly defines sensitive information.

There are three general states from which data may be accessible:

- **At rest** - the data is sitting in a file or data store
- **In use** - an application has loaded the data into its address space
- **In transit** - data has been sent between consuming processes, e.g., during IPC (Inter-Process Communication)

The degree of scrutiny that's appropriate for each state may depend on the data's importance and likelihood of being accessed. For example, data held in application memory may be more vulnerable than data on web servers to access via core dumps because attackers are more likely to gain physical access to mobile devices than to web servers.

When no data classification policy is available, use the following list of information that's generally considered sensitive:

- user authentication information (credentials, PINs, etc.)
- Personally Identifiable Information (PII) that can be abused for identity theft: social security numbers, credit card numbers, bank account numbers, health information
- device identifiers that may identity a person
- highly sensitive data whose compromise would lead to reputational harm and/or financial costs
- any data whose protection is a legal obligation
- any technical data generated by the application (or its related systems) and used to protect other data or the system itself (e.g., encryption keys).

 A definition of "sensitive data" must be decided before testing begins because detecting sensitive data leakage without a definition may be impossible.

##### Intelligence Gathering

Intelligence gathering involves the collection of information about the app's architecture, the business use cases the app serves, and the context in which the app operates. Such information may be classified as "environmental" or "architectural."

###### Environmental Information

Environmental information includes:

- The organization's goals for the app. Functionality shapes users' interaction with the app and may make some surfaces more likely than others to be targeted by attackers.   
- The relevant industry. Different industries may have different risk profiles.
- Stakeholders and investors; understanding who is interested in and responsible for the app.
- Internal processes, workflows, and organizational structures. Organization-specific internal processes and workflows may create opportunities for [business logic exploits](https://www.owasp.org/index.php/Testing_for_business_logic "Testing business logic").

###### Architectural Information

Architectural information includes:

- **The mobile app:** How the app accesses data and manages it in-process, how it communicates with other resources and manages user sessions, and whether it detects itself running on jailbroken or rooted phones and reacts to these situations.
- **The Operating System:** The operating systems and OS versions the app runs on (including Android or iOS version restrictions), whether the app is expected to run on devices that have Mobile Device Management (MDM) controls, and relevant OS vulnerabilities.
- **Network:** Usage of secure transport protocols (e.g., TLS), usage of strong keys and cryptographic algorithms (e.g., SHA-2) to secure network traffic encryption, usage of certificate pinning to verify the endpoint, etc.
- **Remote Services:** The remote services the app consumes and whether their being compromised could compromise the client.

##### Mapping the Application

Once the security tester has information about the app and its context, the next step is mapping the app's structure and content, e.g., identifying its entry points, features, and data. 

When penetration testing is performed in a white-box or grey-box paradigm, any documents from the interior of the project (architecture diagrams, functional specifications, code, etc.) may greatly facilitate the process. If source code is available, the use of SAST tools can reveal valuable information about vulnerabilities (e.g., SQL Injection). 
DAST tools may support black-box testing and automatically scan the app: whereas a tester will need hours or days, a scanner may perform the same task in a few minutes. However, it's important to remember that automatic tools have limitations and will only find what they have been programmed to find. Therefore, human analysis may be necessary to augment results from automatic tools (intuition is often key to security testing). 

Threat Modeling is an important artifact: documents from the workshop usually greatly support the identification of much of the information a security tester needs (entry points, assets, vulnerabilities, severity, etc.). Testers are strongly advised to discuss the availability of such documents with the client. Threat modeling should be a key part of the software development life cycle. It usually occurs in the early phases of a project.

The [threat modeling guidelines defined in OWASP](https://www.owasp.org/index.php/Application_Threat_Modeling "OWASP Application Threat Modeling") are generally applicable to mobile apps.

##### Exploitation

Unfortunately, time or financial constraints limit many pentests to application mapping via automated scanners (for vulnerability analysis, for example). Although vulnerabilities identified during the previous phase may be interesting, their relevance must be confirmed with respect to five axes:

- **Damage potential** - the damage that can result from exploiting the vulnerability
- **Reproducibility** - ease of reproducing the attack
- **Exploitability** - ease of executing the attack
- **Affected users** - the number of users affected by the attack
- **Discoverability** - ease of discovering the vulnerability

Against all odds, some vulnerabilities may not be exploitable and may lead to minor compromises, if any. Other vulnerabilities may seem harmless at first sight, yet be determined very dangerous under realistic test conditions. Testers who carefully go through the exploitation phase support pentesting by characterizing vulnerabilities and their effects.


#### Reporting

The security tester's findings will be valuable to the client only if they are clearly documented. A good pentest report should include information such as, but not limited to, the following:

- an executive summary
- a description of the scope and context (e.g., targeted systems)
- methods used
- sources of information (either provided by the client or discovered during the pentest)
- prioritized findings (e.g., vulnerabilities that have been structured by DREAD classification)
- detailed findings
- recommendations for fixing each defect

Many pentest report templates are available on the internet: Google is your friend!


### Security Testing and the SDLC

Although the principles of security testing haven't fundamentally changed in recent history, software development techniques have changed dramatically. While the widespread adoption of Agile practices was speeding up software development, security testers had to become quicker and more agile while continuing to deliver trustworthy software.

The following section is focused on this evolution and describes contemporary security testing.

#### Security Testing during the Software Development Life Cycle

Software development is not very old, after all, so the end of developing without a framework is easy to observe. We have all experienced the need for a minimal set of rules to control work as the source code grows.

In the past, "Waterfall" methodologies  were the most widely adopted: development proceeded by steps that had a predefined sequence. Limited to a single step, backtracking capability was a serious drawback of Waterfall methodologies. Although they have important positive features (providing structure, helping testers clarify where effort is needed, being clear and easy to understand, etc.), they also have negative ones (creating silos, being slow, specialized teams, etc.).

As software development matured, competition increased and developers needed to react to market changes more quickly while creating software products with smaller budgets. The idea of less structure became popular, and smaller teams collaborated, breaking silos throughout the organization. The "Agile" concept was born (Scrum, XP, and RAD are well-known examples of Agile implementations); it enabled more autonomous teams to work together more quickly.

Security wasn't originally an integral part of software development. It was an afterthought, performed at the network level by operation teams who had to compensate for poor software security! Although unintegrated security was possible when software programs were located inside a perimeter, the concept became obsolete as new kinds of software consumption emerged with web, mobile, and IoT technologies. Nowadays, security must be baked **inside** software because compensating for vulnerabilities is often very difficult.

Implementing a Secure SDLC (Software Development Life Cycle) is the way to incorporate security during software development. Secure SDLCs do not depend on any methodology or language, and they can be used with Waterfall and Agile. This chapter is focused on Agile and Secure SDLC in the DevOps world, and it includes details about state-of-the-art ways to quickly and collaboratively develop and deliver secure software that promotes autonomy and automation.

Note: "SDLC" will be used interchangeably with "Secure SDLC" in the following section to help you internalize the idea that security is a part of software development processes. 
In the same spirit, we use the name DevSecOps to emphasize the fact that security is part of DevOps.

#### SDLC Overview

##### General Description of SDLC

SDLCs always consist of the same steps (the overall process is sequential in the Waterfall paradigm and iterative in the Agile paradigm):

- Perform a **risk assessment** for the application and its components to identify their risk profiles. These risk profiles typically depend on the organization's risk appetite and applicable regulatory requirements. The risk assessment is also based on factors, including whether the application is accessible via the Internet and the kind of data the application processes and stores. All kinds of risks must be taken into account: financial, marketing, industrial, etc. Data classification policies specify which data is sensitive and how it must be secured.
- **Security Requirements** are determined at the beginning of a project or development cycle, when functional requirements are being gathered. **Abuse Cases** are added as use cases are created. Teams (including development teams) may be given security training (such as Secure Coding) if they need it. 
You can use the [OWASP MASVS](https://www.owasp.org/images/f/fe/MASVS_v0.9.3.pdf "OWASP MASVS") to determine the security requirements of mobile applications on the basis of the risk assessment phase. Iteratively reviewing requirements when features and data classes are added is common, especially with Agile projects.
-  **Threat Modeling**, which is basically the identification, enumeration, prioritization, and initial handling of threats, is a foundational artifact that must be performed as architecture development and design progress. **Security Architecture**, a Threat Model factor, can be refined (for both software and hardware aspects) after the Threat Modeling phase. **Secure Coding rules** are established and the list of **Security tools** that will be used is created. The strategy for **Security testing** is clarified.
- All security requirements and design considerations should be stored in the Application Life Cycle Management (ALM) system (also known as the issue tracker) that the development/ops team uses to ensure tight integration of security requirements into the development workflow. The security requirements should contain relevant source code snippets so that developers can quickly reference the snippets. Creating a dedicated repository that's under version control and contains only these code snippets is a secure coding strategy that's more beneficial than the traditional approach (storing the guidelines in word documents or PDFs).
- **Securely develop the software**. To increase code security, you must complete activities such as **Security Code Reviews**, **Static Application Security Testing**, and **Security Unit Testing**. Although quality analogues of these security activities exist, the same logic must be applied to security, e.g., reviewing, analyzing, and testing code for security defects (for example, missing input validation, failing to free all resources, etc.).
- Next comes the long-awaited release candidate testing: both manual and automated **Penetration Testing** ("Pentests"). **Dynamic Application Security Testing** is usually performed during this phase as well.
- After the software has been **Accredited** during **Acceptance** by all stakeholders, it can be safely transitioned to **Operation** teams and put in Production.
- The last phase, too often neglected, is the safe **Decommissioning** of software after its end of use.

The picture below illustrates all the phases and artifacts:
![General description of SDLC](Images/Chapters/0x04b/SDLCOverview.JPG)

Based on the project's general risk profile, you may simplify (or even skip) some artifacts, and you may add others (formal intermediary approvals, formal documentation of certain points, etc.). **Always remember two things: an SDLC is meant to reduce risks associated with software development, and it is a framework that helps you set up controls to that end.** This this is a generic description of SDLC; always tailor this framework to your projects.

##### Defining a Test Strategy

Test strategies specify the tests that will be performed during the SDLC as well as testing frequency. Test strategies are used to make sure that the final software product meets security objectives, which are generally determined by clients' legal/marketing/corporate teams. 
The test strategy is usually created during the Secure Design phase, after risks have been clarified (during the Initiation phase) and before code development (the Secure Implementation phase) begins. The strategy requires input from activities such as Risk Management, previous Threat Modeling, and Security Engineering.

A Test Strategy needn't be formally written: it may be described through Stories (in Agile projects), quickly enumerated in checklists, or specified as test cases for a given tool. However, the strategy must definitely be shared because it must be implemented by a team other than the team who defined it. Moreover, all technical teams must agree to it to ensure that it doesn't place unacceptable burdens on any of them.

Test Strategies address topics such as the following:

- objectives and risk descriptions
- plans for meeting objectives, risk reduction, which tests will be mandatory, who will perform them, how and when they will be performed
- acceptance criteria

To track the testing strategy's progress and effectiveness, metrics should be defined, continually updated during the project, and periodically communicated. An entire book could be written about choosing relevant metrics; the most we can say here is that they depend on risk profiles, projects, and organizations. Examples of metrics include the following:

- the number of stories related to security controls that have been successfully implemented
- code coverage for unit tests of security controls and sensitive features
- the number of security bugs found for each build via static analysis tools
- trends in security bug backlogs (which may be sorted by urgency)

These are only suggestions; other metrics may be more relevant to your project. Metrics are powerful tools for getting a project under control, provided they give project managers a clear and synthetic perspective on what is happening and what needs to be improved.

Distinguishing between tests performed by an internal team and tests performed by an independent third party is important. Internal tests are usually useful for improving daily operations, while third-party tests are more beneficial to the whole organization. Internal tests can be performed quite often, but third-party testing happens at most once or twice a year; also, the former are less expensive than the latter. 
Both are necessary, and many regulations mandate tests from an independent third party because such tests can be more trustworthy.

#### Security Testing in Waterfall

##### What Waterfall Is and How Testing Activities Are Arranged

Basically, SDLC doesn't mandate the use of any development life cycle: it is safe to say that security can (and must!) be addressed in any situation. 

Waterfall methodologies were popular before the 21st century. The most famous application is called the "V model," in which phases are performed in sequence and you can backtrack only a single step.
The testing activities of this model occur in sequence and are performed as a whole, mostly at the point in the life cycle when most of the app development is complete. This activity sequence means that changing the architecture and other factors that were set up at the beginning of the project is hardly possible even though code may be changed after defects have been identified.

#### Security Testing for Agile/DevOps and DevSecOps

DevOps refers to practices that focus on a close collaboration between all stakeholders involved in software development (generally called Devs) and operations (generally called Ops). DevOps is not about merging Devs and Ops. 
Development and operations teams originally worked in silos, when pushing developed software to production could take a significant amount of time. When development teams made moving more deliveries to production necessary by working with Agile, operation teams had to speed up to match the pace. DevOps is the necessary evolution of the solution to that challenge in that it allows software to be released to users more quickly. This is largely accomplished via extensive build automation, the process of testing and releasing software, and infrastructure changes (in addition to the collaboration aspect of DevOps). This automation is embodied in the deployment pipeline with the concepts of Continuous Integration and Continuous Delivery (CI/CD).

People may assume that the term "DevOps" represents collaboration between development and operations teams only, however, as DevOps thought leader Gene Kim puts it: "At first blush, it seems as though the problems are just between dev and ops, but test is in there, and you have information security objectives, and the need to protect systems and data. These are top-level concerns of management, and they have become part of the DevOps picture."

In other words, DevOps collaboration includes quality teams, security teams, and many other teams related to the project. When you hear "DevOps" today, you should probably be thinking of something like [DevOpsQATestInfoSec](https://techbeacon.com/evolution-devops-new-thinking-gene-kim "The evolution of DevOps: Gene Kim on getting to continuous delivery"). Indeed, DevOps values pertain to increasing not only speed but also quality, security, reliability, stability, and resilience. 

Security is just as critical to business success as the overall quality, performance, and usability of an application. As development cycles are shortened and delivery frequencies increased, making sure that quality and security are built in from the very beginning becomes essential. **DevSecOps** is all about adding security to DevOps processes. Most defects are identified during production. DevOps specifies best practices for identifying as many defects as possible early in the life cycle and for minimizing the number of defects in the released application.

However, DevSecOps is not just a linear process oriented towards delivering the best possible software to operations; it is also a mandate that operations closely monitor software that's in production to identify issues and fix them by forming a quick and efficient feedback loop with development. DevSecOps is a process through which Continuous Improvement is heavily emphasized.

![DevSecOps process](Images/Chapters/0x04b/DevSecOpsProcess.JPG)

The human aspect of this emphasis is reflected in the creation of cross-functional teams that work together to achieve business outcomes. This section is focused on necessary interactions and integrating security into the development life cycle (which starts with project inception and ends with the delivery of value to users).

##### What Agile and DevSecOps Are and How Testing Activities Are Arranged

###### Overview

Automation is a key DevSecOps practice: as stated earlier, the frequency of deliveries from development to operation increases when compared to the traditional approach, and activities that usually require time need to keep up, e.g. deliver the same added value while taking more time. Unproductive activities must consequently be abandoned, and essential tasks must be fastened. These changes impact infrastructure changes, deployment, and security:
- infrastructure is being implemented as **Infrastructure as Code**
- deployment is becoming more scripted, translated through the concepts of **Continuous Integration** and **Continuous Delivery**
- **security activities** are being automated as much as possible and taking place throughout the life cycle

The following sections provide more details about these three points.

###### Infrastructure as Code

Instead of manually provisioning computing resources (physical servers, virtual machines, etc.) and modifying configuration files, Infrastructure as Code is based on the use of tools and automation to fasten the provisioning process and make is more reliable and repeatable. Corresponding scripts are often stored under version control to facilitate sharing and issue resolution. 

Infrastructure as Code practices facilitate collaboration between development and operations teams, with the following results: 
- Devs better understand infrastructure from a familiar point of view and can prepare resources that the running application will require.
- Ops operate an environment that better suits the application, and they share a language with Devs.

Infrastructure as Code also facilitates the construction of the environments required by classical software creation projects, for **development** ("DEV"), **integration** ("INT"), **testing** ("PPR" for Pre-Production. Some tests are usually performed in earlier environments, and PPR tests mostly pertain to non-regression and performance with data that's similar to data used in production), and **production** ("PRD"). The value of infrastructure as code lies in the possible similarity between environments (they should be the same). 

Infrastructure as Code is commonly used for projects that have Cloud-based resources because many vendors provide APIs that can be used for provisioning items (such as virtual machines, storage spaces, etc.) and working on configurations (e.g., modifying memory sizes or the number of CPUs used by virtual machines). These APIs provide alternatives to administrators' performing these activities from monitoring consoles.

The main tools in this domain are Puppet ([Puppet](https://puppet.com/ "Puppet")) and Chef ([Chef](https://www.chef.io/chef/ "Chef")).

###### Deployment

The deployment pipeline's sophistication depends on the maturity of the project organization or development team. In its simplest form, the deployment pipeline consists of a commit phase. The commit phase usually involves running simple compiler checks and the unit test suite as well as creating a deployable artifact of the application. A release candidate is the latest version that has been checked into the trunk of the version control system. Release candidates are evaluated by the deployment pipeline for conformity to standards they must fulfill for deployment to production.

The commit phase is designed to provide instant feedback to developers and is therefore run on every commit to the trunk. Time constraints exist because of this frequency. The commit phase should usually be complete within five minutes, and it shouldn't take longer than ten. Adhering to this time constraint is quite challenging when it comes to security because many security tools can't be run quickly enough (#paul, #mcgraw).

CI/CD means "Continuous Integration/Continuous Delivery" in some contexts and "Continuous Integration/Continuous Deployment" in others. Actually, the logic is:
- Continuous Integration build actions (either triggered by a commit or performed regularly) use all source code to build a candidate release. Tests can then be performed and the release's compliance with security, quality, etc., rules can be checked. If case compliance is confirmed, the process can continue; otherwise, the development team must remediate the issue(s) and propose changes.
- Continuous Delivery candidate releases can proceed to the pre-production environment. If the release can then be validated (either manually or automatically), deployment can continue. If not, the project team will be notified and proper action(s) must be taken.
- Continuous Deployment releases are directly transitioned from integration to production, e.g., they become accessible to the user. However, no release should go to production if significant defects have been identified during previous activities.

The delivery and deployment of applications with low or medium sensitivity may be merged into a single step, and validation may be performed after delivery. However, keeping these two actions separate and using strong validation are strongly advised for sensitive applications.

###### Security

At this point, the big question is: now that other activities required for delivering code are completed significantly faster and more effectively, how can security keep up? How can we maintain an appropriate level of security? Delivering value to users more often with decreased security would definitely not be good!

Once again, the answer is automation and tooling: by implementing these two concepts throughout the project life cycle, you can maintain and improve security. The higher the expected level of security, the more controls, checkpoints, and emphasis will take place. The following are examples:
- Static Application Security Testing can take place during the development phase, and it can be integrated into the Continuous Integration process with more or less emphasis on scan results. You can establish more or less demanding Secure Coding Rules and use SAST tools to check the effectiveness of their implementation.
- Dynamic Application Security Testing may be automatically performed after the application has been built (e.g., after Continuous Integration has taken place) and before delivery, again, with more or less emphasis on results.
- You can add manual validation checkpoints between consecutive phases, for example, between delivery and deployment. 

The security of an application developed with DevOps must be considered during operations. The following are examples:
- Scanning should take place regularly (at both the infrastructure and application level).
- Pentesting may take place regularly. (The version of the application used in production is the version that should be pentested, and the testing should take place in a dedicated environment and include data that's similar to the production version data. Cf the section on Penetration Testing for more details.)
- Active monitoring should be performed to identify issues and remediate them as soon as possible via the feedback loop.

The level of security of a DevSecOps process should always be the reader's responsibility. Here is an example process:

![Example of a DevSecOps process](Images/Chapters/0x04b/ExampleOfADevSecOpsProcess.JPG)


### References

- [paul] - M. Paul. Official (ISC)2 Guide to the CSSLP CBK, Second Edition ((ISC)2 Press), 2014
- [mcgraw] - G McGraw. Software Security: Building Security In, 2006











Throughout the guide, we use "mobile app security testing" as a catch-all phrase for evaluating the security of mobile apps using static and dynamic analysis. In practice, you'll find that various terms such as "mobile app penetration testing", "mobile app security review", and others are used somewhat inconsistently in the security industry, but those terms refer to roughly the same thing. Usually, a mobile app security test is done as part of a larger security assessment or penetration test that also encompasses the overall client-server architecture, as well as server-side APIs used by the mobile app.

In this guide we cover mobile app security testing in two different contexts. The first one is the "classical" security test done towards the end of the development life cycle. Here, the tester gets access to a near-final or production-ready version of the app, identifies security issues, and writes a (usually devastating) report. The other context is implementing requirements and automating security tests from the beginning of the software development life cycle. In both cases, the same basic requirements and test cases apply, but there's a difference in the high-level methodology and level of interaction with the client.

### Vulnerability Analysis Overview

Vulnerability analysis is the process of identifying security vulnerabilities in an app. Generally, we distinguish between *static analysis* and *dynamic analysis*. 

#### Static Analysis

In static analysis, the source code or binary code of the mobile app is analyzed to ensure sufficient and correct implementation of security controls. Notably, static analysis can be applied without executing the app. In most cases, a hybrid automated / manual approach is used: Automated scans catch the low-hanging fruits, while the human tester can explore the code base with specific business and usage contexts in mind, providing enhanced relevance and coverage. Today, the buzzword-acronym "SAST" ("Static Application Security Testing") is often used to refer to static analysis.

OWASP provides great resources on [Static Code Analysis](https://www.owasp.org/index.php/Static_Code_Analysis "OWASP Static Code Analysis") which can help in understanding the techniques to be used, its strengths and weaknesses and its limitations.

##### Automated Static Analysis

Automated analysis tools check the source code for compliance with a predefined set of rules or industry best practices. The tool then typically displays a list of findings or warnings and flags all detected violations. Static analysis tools come in different varieties - some only run against the compiled app, some need to be fed with the original source code, and some run as live-analysis plugins in the Integrated Development Environment (IDE).

While some static code analysis tools do encapsulate a deep knowledge of the underlying rules and semantics required to perform analysis of mobile apps, they can produce a high number of false positives, particularly if the tool is not properly configured for the target environment. The results must therefore always be reviewed by a security professional.

A list of static analysis tools can be found in the chapter "Testing tools".

##### Manual Code Analysis

In manual code analysis, a human reviewer manually analyzes the source code of the mobile application for security vulnerabilities. Methods range from a basic keyword search with the 'grep' command to identify usages of potentially vulnerable code patterns, to detailed line-by-line reading of the source code. IDEs (Integrated Development Environments) often provide basic code review functionalities and can be extended through different tools to assist in the reviewing process.

A common approach is to identify key indicators of security vulnerabilities by searching for certain APIs and keywords. For example, database-related method calls like "executeStatement" or "executeQuery" are key indicators which may be of interest. Code locations containing these strings are good starting points for manual analysis.

Compared to automatic code analysis tools, manual code review excels at identifying vulnerabilities in the business logic, standards violations and design flaws, especially in situations where the code is technically secure but logically flawed. Such scenarios are unlikely to be detected by any automatic code analysis tool.

A manual code review requires an expert human code reviewer who is proficient in both the language and the frameworks used in the mobile application. Full code review can be time-consuming, slow and tedious for the reviewer, especially for large code bases with many dependencies.

#### Dynamic Analysis

Dynamic Analysis deals with examining the app from the outside when executing it. It can be either manual or automatic. It usually does not provide the same information as Static Analysis and is a good manner to detect interesting elements (assets, features, entry points, ...) with a user point of view. Sometimes, it can be close to black-box testing.

In dynamic analysis (also called DAST for Dynamic Application Security Testing), the focus is on testing and evaluating an app by executing it in real-time. The main objective of dynamic analysis is to find security vulnerabilities or weak spots in a program while it is running. Dynamic analysis is conducted both at the mobile platform layer and is usually also conducted against the back-end services and APIs of mobile applications, where its request and response patterns can be analyzed.

Usually, dynamic analysis is performed to check whether there are sufficient security mechanisms in place against the most prevalent types of attacks like disclosure of data in transit, authentication and authorization issues and server configuration errors.

##### Pros of Dynamic Analysis

Dynamic analysis must be used in coordination with static analysis: it is not a silver bullet (for instance, there are flaws that can not be found by dynamic analysis alone) and has its pros and cons. Pros are:

- Does not require access to the source code and other kind of documentation,
- Able to identify infrastructure, configuration and patch issues that static analysis tools may miss.

##### Cons of Dynamic Analysis

Cons of dynamic analysis are:

- Limited scope of coverage because the mobile application must be foot-printed to identify the specific test area,
- No access to the actual instructions being executed, as the tool exercises the mobile application and conducts pattern matching on requests and responses.

#### Penetration Testing (a.k.a. Pentesting)

The classical approach is to perform all-around security testing of the mobile app and its environment on the final or near-final build of the app, e.g. at the end of the development process. In that case, we recommend using the [Mobile App Security Verification Standard (MASVS)](https://github.com/OWASP/owasp-masvs "OWASP MASVS") and the associated checklist as a reference. A typical security test is structured as follows:

- **Preparation** - defining the scope of security testing, such as which security controls are applicable, what goals the development team and organization have for the testing, and what has been identified as sensitive data in the context of the test. More generally speaking, it includes all activities to synchronize with the client and legally protect the tester (often a third-party) for the activities to come. (remember, attacking a system without proper written authorization is illegal in many parts of the world!).
- **Intelligence Gathering** - involves analyzing the **environmental** and **architectural** context of the app, to gain a general contextual understanding of the app.
- **Mapping the Application** - takes as input information from the previous phases; may be complemented by scanning with automated tools and manually playing with the app. This gives a quite thorough understanding of the app, its entry points, the data it holds and give an idea of the main potential vulnerabilities. These vulnerabilities can then be ranked by order of severity and therefore gives the security tester a prioritized list of items he should start with. Produces test cases that may be used during test execution.
- **Exploitation** - this is the phase when the security tester tries to penetrate the app by using the vulnerabilities identified during the previous phase using security tools and techniques. This phase is needed to confirm whether vulnerabilities are real (true positives) or do not lead to any compromise (false positives).
- **Reporting** - essential to the client, this is the moment when the security tester writes a report to list the vulnerabilities he has been able to exploit and document the kind of compromise he has been able to perform and its scope (for instance, which data he has been able to get access to illegitimately).

#### White-box Versus Black-box Testing

Let's start by defining the concepts:

- black-box testing is a kind of testing where no knowledge about the app under test is given to the tester. This is sometimes called "zero-knowledge testing". The main interest of this kind of tests is to behave like a real attacker and see what is possible when using publically available or discoverable information.
- white-box testing is the total opposite of black-box testing in that, in this situation, full knowledge about the app is given to the tester: that may include source code, documentations, diagrams, ... While testing in such conditions is way easier and faster than in black-box conditions, it does not allow the checking of as many test cases as black-box. It is generally more purposeful for improving the app against internal attackers. This is sometimes referred to as "full knowledge testing".
- all kinds of testing in between the two previous kinds of tests are called grey-box testing: this is when some information is provided to the tester, but some other is left to find. This is an interesting compromise when it comes to the number of test cases checked, cost, speed and depth of testing. This is the more frequent kind of testing used in the industry.

In order to spend the allocated time for tests as efficiently as possible for a mobile security test, it is strongly advised to request the source code to support testing. Obviously this does not really represent the scenario of an external attacker but this so called white-box testing will make it much easier to identify vulnerabilities, as every anomaly or suspicious behavior you identify can be verified on the code level. Especially if the app is tested the first time a white-box test is the way to go.

Even though decompiling is straightforward on Android, the source code might be obfuscated, which will be time-consuming or even not possible to de-obfuscate in the time you have. Therefore, again the source code should be provided to be able to focus on the overall security of the app.

Black-box testing might still be requested by the client, but it should be made clear that an external attacker always has as much time as he wants and not only a limited time frame as you. Therefore, black-box testing might be a good choice if the app is already mature from a security point of view and if the client wants to test the implemented security controls and their effectiveness.

#### Avoiding False Positives

The challenge with automated testing is that, often, tools are not aware of the context of an app. Consequently, these tools may identify a potential issue that is not one in the given situation. These are called 'False positives'.

For instance, a common pitfall for security testers is reporting issues that would be exploitable in a web browser, but aren't relevant in the context of the mobile app. The reason for this is that automated tools used to scan the back-end service assume a regular, browser based web application. Issues such as CSRF, missing security headers and others are reported accordingly.

Let's take CSRF as an example: a successful CSRF attack requires the following:

1. It must be possible to entice the logged-in user to open a malicious link in the same web browser used to access the vulnerable site;
2. The client (browser) must automatically add the session cookie or other authentication token to the request.

Mobile apps don't fulfill these requirements: even if Webviews and cookie-based session management were used, any malicious link clicked by the user would open in the default browser which has its own, separate cookie store.

Stored Cross-Site Scripting (CSS) can be an issue when the app uses Webviews, and potentially even lead to command execution if the app exports JavaScript interfaces. However, reflected cross-site scripting is rarely an issue for the same reasons stated above (even though one could argue that they shouldn't exist either way - escaping output is simply a best practice that should always be followed).

In any case, think about the actual exploit scenarios and impacts of the vulnerability when performing the risk assessment - don't blindly trust the output of your scanning tool.

### Performing a Security Test

#### Preparation

Before conducting the technical analysis, it is useful to map out a simple threat model and assess the security requirements of the target app (this can be done informally in a pre-kickoff discussion with the client). Depending on the maturity of the client's software development processes, they may have a clear idea about the specific security requirements pertaining to the app - or they might not have given it much thought. 

![Preparation](Images/Chapters/0x03/mstg-preparation.png)

##### Testing Environment

Setting up a working testing environment can be a challenging task. For instance, when performing testing on-site at client premises, the restrictions on the enterprise wireless access points and networks may make dynamic analysis more difficult. Company policies may prohibit the use of rooted phones or network testing tools (hardware and software) within the enterprise networks. Apps implementing root detection and other reverse engineering countermeasures may add a significant amount of extra work before further analysis can be performed.

Security testing involves many invasive tasks such as monitoring and manipulating the network traffic between the mobile app and its remote endpoints, inspecting the app data files, and instrumenting API calls. Security controls like certificate pinning and root detection might impede these tasks and slow down testing dramatically.

To overcome these obstacles, it might make sense to request two build variants of the app from the development team. One variant should be provided as a release build to check if the implemented controls like certificate pinning are working properly or can easily be bypassed. The second variant should also be provided as a debug build that deactivates certain security controls. This approach makes it possible to cover all scenarios and test cases in the most efficient way.

Of course, depending on the scope of the engagement, such approach may not be possible. For a white-box test, requesting both production and debug builds will help to go through all test cases and give a clear statement of the security maturity of the app. For a black-box test, the client might prefer the test to be focused on the production app, with the goal of evaluating the effectiveness of its security controls.

For both types of testing engagements, the scope should be discussed during the preparation phase. For example, it should be decided whether the security controls should be adjusted or not. Additional topics to cover are discussed below.

##### Classifying Data

Classification of sensitive information can vary between different industries and countries. Beyond legal and civic obligations, organizations may take a more restrictive view of what counts as sensitive data, and may have a data classification policy that clearly defines what counts as sensitive information.

There are three general states in which data may be accessible:

- **At rest** - when the data is sitting in a file or data store,
- **In use** - when an application has load the data into its address space,
- **In transit** - when data has been sent between consuming processes - e.g. during IPC (Inter-Process Communication).

The degree of scrutiny to apply to each state may depend on the criticality of the data, and likelihood of access. For example, because the likelihood of malicious actors gaining physical access to mobile devices is greater, data held in application memory may be more at risk of being accessed via core dumps than that on a web-server.

In order to provide guidance when no data classification policy is available, the following kinds of information are generally considered to be sensitive:

- User authentication information (credentials, PINs etc.),
- Personal Identifiable Information (PII) that can be abused for identity theft: Social security numbers, credit card numbers, bank account numbers or health information,
- Device identifiers that might allow to identity a person,
- Highly sensitive data that would lead to reputational harm and / or financial costs if compromised,
- Any data that must be protected by law or for compliance reasons,
- Finally, any technical data generated by the application or its related systems that is used to protect other data or the system should also be considered as sensitive information (e.g. encryption keys).

It may be impossible to detect leakage of sensitive data without a firm definition of what counts as such, so such a definition must be agreed upon in advance of testing.

##### Information Gathering

Information gathering involves the collection of information about the architecture of the app, the business use cases it serves, and the context in which it operates. Such information may be broadly divided into "environmental" and "architectural".

###### Environmental Information

Environmental information concerns understanding:

- The goals the organization has for the app. What the app is supposed to do shapes the ways users are likely to interact with it, and may make some surfaces more likely to be targeted than others by attackers.   
- The industry in which they operate. Specific industries may have differing risk profiles, and may be more or less exposed to particular attack vectors.
- Stakeholders and investors. Understanding who is interested in and responsible for the app.
- Internal processes, workflows and organizational structures. Organization-specific internal processes and workflows may create opportunities for [business logic exploits](https://www.owasp.org/index.php/Testing_for_business_logic "Testing business logic").

###### Architectural Information

Architectural information concerns understanding:

- **The mobile app:** How the app accesses data and manages it in-process, how it communicates with other resources, manages user sessions, and whether it detects and reacts to running on jailbroken or rooted phones.
- **The Operating System:** What operating systems and versions does the app run on (e.g. is it restricted to only newer Android or iOS versions, and do we need to be concerned about vulnerabilities in earlier OS versions), is it expected to run on devices with Mobile Device Management (MDM) controls, and what OS vulnerabilities might be relevant to the app.
- **Network:** Are secure transport protocols used (e.g. TLS), is network traffic encryption secured with strong keys and cryptographic algorithms (e.g. SHA-2 for instance), is certificate pinning used to verify the endpoint, etc.
- **Remote Services:** What remote services does the app consume, if they were compromised, could the client by compromised.

##### Mapping the Target App

Now that the security tester has information on the nature of the app and its context, the next step is to map its structure and content, e.g. identify its entry points, the features it contains, the data is holds and all other interesting elements to be targeted. 

When penetration testing is performed in a white-box or grey-box manner, all documents from the interior of the project may greatly help and fasten the process: architecture diagrams, functional specifications, code, ... In case source code is available, using SAST tools can reveal valuable information concerning vulnerabilities (SQL Injection, ...). 
When working in black-box mode, DAST tools may provide support and automatically scan the app: when a tester will need hours or days, a scanner may need only a few minutes to perform the same task. However, an important point is that automatic tools still have limitations and will only find what they have been programmed for. As such, human analysis may be needed to add to results from automatic tools (intuition is often key in security testing). 

An artifact to be mentioned is Threat Modeling: when documents from the workshop are available, they usually provide great support in identifying much information a security tester needs (entry points, assets, vulnerabilities, severity, ...). It is strongly advised to discuss the availability of such documents with the client. Threat modeling should be a key part of the software development life cycle and generally happens in the early steps of a project.

The [threat modeling guidelines defined by OWASP](https://www.owasp.org/index.php/Application_Threat_Modeling "OWASP Application Threat Modeling") are generally applicable to mobile apps.

##### Testing for Vulnerabilities

This phase is where the actual fun starts: The tester uses static and dynamic analysis methods to discover vulnerabilities. The methods to do so range from basic automated scanning to manual inspection of the business logic and instrumentation of system APIs. This is where the OWASP Mobile Security Testing Guide comes in: You'll find all the necessary tricks and techniques in this book.

##### Exploitation

Unfortunately, due to shortage of time or limited financial resources, many penetration tests are limited to vulnerability discovery, often using automated scanners (for instance, for vulnerability analysis). While vulnerabilities identified during the previous phase may be interesting, the reality of their effectiveness need to be confirmed on five axes:

- **Damage potential** - the damage(s) to which the vulnerability can lead if exploited successfully,
- **Reproducibility** - how easy it is to reproduce the attack,
- **Exploitability** - how easy it is to perform the attack,
- **Affected users** - how many users are affected by the attack,
- **Discoverability** - how easy it is to discover the vulnerability.

Indeed, against all odds, some vulnerabilities may not be exploitable and may not lead to any compromise or lead to minor ones. In the opposite manner, some others vulnerabilities may seem harmless at first sight while the tester may find them highly dangerous for the application when testing in real conditions. Performing the exploitation phase with care increases the value of the penetration test by characterizing vulnerabilities and proving information on their impacts.

#### Reporting

All the findings the security tester will make during the different phases will be valuable to the customer only as they are clearly documented. A good pentest report will need to include information like (but not limited to):

- an executive summary,
- description of the scope and context (targeted systems, ...),
- methodology used,
- sources of information (either provided by the client or discovered during the pentest),
- prioritized findings (vulnerabilities that have been structured by DREAD classification for instance),
- detailed findings,
- recommendations for fixing each defect.

Many templates can be found on the internet: Google is your friend!

### Security Testing in the Software Development Life Cycle

Even if the principles of security testing have not fundamentally changed in recent history, the way to develop software changed dramatically. While software development became quicker with the wide adoption of Agile practices, security testing had to keep up and to become more agile and quicker, while still providing a high degree of confidence in delivered software.

The following sections will focus on this evolution and will provide elements on modern ways security testing is performed.

#### Software Development Practices and Security

The history of software development is not that old after all, and it is easy to see that, rapidly, teams have stopped developing programs without any framework: we have all experienced the fact that, as the number of lines of code grows, a minimal set of rules are needed in order to keep work under control, meet deadlines, quality targets and budgets.

In the past, the most widely adopted methodologies were from the "Waterfall" family: development was done from a starting point to a final one, going through several steps, each of them happening one after the other in a predefined sequence. In case something was wrong during a given phase and something had to be changed in a former phase, unfortunately it was possible to go only one step backward, raising many issues when problems where originating from earlier phases. This was a serious drawback of Waterfall methodologies. Even if they have strong positive points (bring structure, clarify where to put effort, clear and easy to understand, ...), they also have negative ones (poor flexibility, creation of silos, slow, specialized teams, ...).

As time was passing and software development was maturing, also competition was getting stronger and stronger, and a need to react faster to market changes while creating software products with smaller budgets rose. The idea of having more flexibility became popular, with smaller teams collaborating together, breaking silos through the organization from marketing to production. Along with the introduction of Lean practices in software development, the "Agile" concept was born (well-known examples of Agile implementations are Scrum, XP and RAD), which was enabling more autonomous teams to work together in a faster manner.

Originally, security was not an integral part of software development. It was seen as an afterthought, and was performed by Operation teams often mostly at the network level: those teams had to find ways to compensate for poor security in software programs! However, while this was possible when software programs were located inside a perimeter, the concept became obsolete as new ways to consume software emerged with Web, Mobile and IoT technologies. Nowadays, security has to be baked **inside** software as it is often very hard in this new paradigm without a perimeter to compensate for existing vulnerabilities.

The way to incorporate security during software development is to put in place a Secure SDLC (Software Development Life Cycle). A Secure SDLC does not depend on any methodology nor on any language, and it is possible to incorporate one in Waterfall or Agile: no excuse not to use one! In the coming sections, while all principles will be true in the Waterfall world, we will focus on Agile and Secure SDLC, and in particular on the DevOps (DevSecOps) world. The reader will find below details on state-of-the-art ways to develop and deliver secure software in a fast-paced and collaborative manner that promotes autonomy and automation.

Note: SDLC will be used interchangeably with Secure SDLC in the coming paragraphs, e.g. the assumption that security is part of a software development process needs to become natural to the reader. 
Also, in the same spirit, DevSecOps is the name used when there is a need to emphasize the fact that security is part of DevOps. However, we'll assume that security is naturally part of DevOps!

#### Agile and DevSecOps

DevOps refers to practices that focus on a close collaboration between all stakeholders involved in software development (generally called Devs) and operation (generally called Ops). It is not about merging Devs and Ops. 
Originally, development and operations teams were working in silos; pushing developed software to production could take a significant amount of time. As development teams were starting to work in Agile, resulting in the need to move more and more deliveries to production, operation teams had to find a solution to speed up and move at the same pace. DevOps is the necessary evolution to that challenge in that it enables software to be released to users in a faster manner. Besides the collaboration aspect, to a large extent, this is facilitated through heavy automation of the build, test and release process of software and infrastructure changes. This automation is embodied in the deployment pipeline with the concepts of Continuous Integration and Continuous Delivery (CI / CD).

The term DevOps might be mistaken for only expressing collaboration between development and operations teams, however, as Gene Kim, a DevOps thought leader, puts it: "At first blush, it seems as though the problems are just between dev and ops," he says, "but test is in there, and you have information security objectives, and the need to protect systems and data. These are top-level concerns of management, and they have become part of the DevOps picture."

In other words, DevOps refers to many more things than just development and operations teams working together: it involves of course Devs and Ops, but also quality and security teams, and many other teams depending on the project itself. When you hear "DevOps" today, you should probably be thinking of something like [DevOpsQATestInfoSec](https://techbeacon.com/evolution-devops-new-thinking-gene-kim "The evolution of DevOps: Gene Kim on getting to continuous delivery"). Indeed, DevOps values are to increase speed, but also quality, security, reliability, stability and resilience. 

Security is just as important for the business success as the overall quality, performance and usability of an application. As development cycles are shortened and delivery frequencies increased, it is essential to ensure that quality and security are built in from the very beginning. **DevSecOps** is all about bringing security in the DevOps process. Whereas most of defects were found in production in the past, it puts in place best practices to identify the maximum of defects early in the lifecycle and to minimize the number of defects that are present in the released application.

However, DevSecOps is not a linear process with the single goal of delivering the best possible software to operations: it also mandates that operations closely monitor software in production to identify issues and incorporate a quick and efficient feedback loop with development to fix these issues. DevSecOps is a process that puts a heavy emphasis on Continuous Improvement.

![DevSecOps process](Images/Chapters/0x04b/DevSecOpsProcess.JPG)

From the human aspect, this is achieved by creating cross functional teams that work together on achieving business outcomes. This section is going to focus on necessary interactions and on the integration of security into the development lifecycle, from project inception all the way down to the delivery of value to users.

#### Building Security into the SDLC

Whatever the development methodology that is being used, a SDLC always follows the same process (either sequentially in Waterfall or iteratively in Agile):

- Perform a **Risk Assessment** of the application and its components to identify their respective risk profiles. These risk profiles are linked to the risk appetite of the organization and the regulatory requirements for the application under consideration. The risk assessment is additionally influenced by other factors such as whether the application is accessible from the Internet or not, or what kind of data is processed and stored. All sorts of risks need to be taken into account : financial, marketing, industrial, ... It is strongly advised to have a data classification policy to help determine which data is considered sensitive and prescribe how this data has to be secured;
- At the beginning of a project or a development cycle, at the same time when functional requirements are gathered, **Security Requirements** are listed and clarified. As use cases are built, **Abuse Cases** are added. Teams (including development teams) may be trained on security(Secure Coding, ...). 
For mobile applications, the [OWASP MASVS](https://www.owasp.org/images/f/fe/MASVS_v0.9.3.pdf "OWASP MASVS") can be leveraged to determine the security requirements based on the risk assessment that was conducted in the initial step. It is common, especially for Agile projects, to iteratively review the set of requirements based on newly added features and new classes of data that is handled by the application.
All security requirements and design considerations should be stored in the Application Life cycle Management (ALM) System, which is typically known as issue tracker, that the development / ops team already uses to ensure that security requirements are tightly integrated into the development workflow. The security requirements should ideally also contain the relevant source code snippets for the used programming language, to ensure that developers can quickly reference them. Another strategy for secure coding guidelines is to create a dedicated repository under version control, that only contains these code snippets, which has many benefits over the traditional approach of storing these guidelines in word documents or PDFs;
- Then, as architecture and design are ongoing, a foundational artifact must be performed: **Threat Modeling**, which is basically an activity where threats are identified, enumerated, prioritized and their treatment initialized. An input of the Threat Model is the **Security Architecture**, but which can be refined after Threat Modeling (both for software and hardware aspects). **Secure Coding rules** are established and the list of **Security tools** that will be used is created. Also, the strategy for **Security testing** is clarified;
- The next step is to **securely develop software**. In order to improve the security level of produced code, some security activities need to be performed, including **Security Code Reviews**, **Static Application Security Testing (SAST)** and **Security Unit Testing**. While these activities have their equivalents for quality, the same logic needs to be applied for security, e.g. reviewing, analyzing and testing code for security defects (for instance, missing validation of inputs, failing to free all resources, ...) and managing these defects (ideally, fixing them) prior to passing code to the next steps;
- Then comes the long-awaited moment to perform tests on the release candidate as a whole: **Penetration Testing** ("Pentests"), using both manual and automated techniques; **Dynamic Application Security Testing (DAST)** is also generally performed during this phase;
- And finally, after software has been **Accredited** during **Acceptance** by all stakeholders, it can be safely transitioned to **Operation** teams and put in Production.
- The last phase, too often neglected, is about safely **Decommissioning** software and its data after its end of use.

The picture below shows all the phases with the different artifacts:
![General description of SDLC](Images/Chapters/0x04b/SDLCOverview.jpg)

Based on the general risk profile of the project, some artifacts may be simplified (or even skipped) while others may be added (formal intermediary approvals, formal documentation of certain points, ...). **Always keep in mind a SDLC is meant to bring risk reduction to software development and is a framework that helps put in place controls that will reduce those risks to an acceptable level.** While this is a generic description of SDLC, always tailor this framework to the needs of your projects and organization.

#### Defining a Test Strategy

The purpose of a test strategy is to define which tests will be performed all along the SDLC and how often. Its goal is to make sure security objectives are met by the final software product, which are generally expressed by customers and / or legal / marketing / corporate teams, while being cost-effective. 

The test strategy is generally created at the beginning of a project in the Secure Design phase, after risks have been clarified (Initiation phase) but before code development (Secure Implementation phase) starts. It takes inputs from activities such as Risk Management, previous Threat Modeling (if any), Security Engineering, etc.

A Test Strategy does not always need to be formally written: it may be described through Stories (in Agile projects), quickly written in the form of checklists, or test cases could be written in a given tool; however, it definitely needs to be shared, as it may be defined by the Architecture team, but will have to be implemented by other teams such as Development, Testing, QA. Moreover, it needs to be agreed upon by all technical teams as it should not place unacceptable burdens on any of them.

Ideally, a Test Strategy addresses topics such as:

- Objectives to be met and description of risks to be put under control,
- How these objectives will be met and risks reduced to an acceptable level: which tests will be mandatory, who will perform them, how, when, and at which frequency,
- Acceptance criteria of the current project.

In order to follow its effectiveness and progress, metrics should be defined, updated all along the project and periodically communicated. An entire book could be written on the relevant metrics to choose; the best that can be said is that they depend on risk profiles, projects and organizations. However, some examples of metrics include:

- The number of stories related to security controls that have been successfully implemented,
- Code coverage for unit tests on security controls and sensitive features,
- The number of security bugs found by static analysis tools upon each build,
- The trend of the backlog for security bugs (may be sorted by criticality).

These are only suggestions, and other metrics may be even more relevant in your case. Metrics are really powerful tools to get a project under control, provided they give a clear and synthetic view to project managers on what is happening and what needs to be improved to reach targets.

It is important to distinguish between two kinds of tests: tests performed by an internal team and tests performed by an independent third-party. Generally speaking, internal tests are useful to improve daily operations, while third-part tests are more beneficial to the whole organization. However, internal tests can be performed quite often when third-party tests happen once or twice a year at best; also, the first kind are less expensive while the other one requires a significant budget. 

Both are needed, and many regulations mandate tests from an independent third-party as they can be more trusted.

##### Security Testing in Waterfall

Basically, SDLC does not mandate the use of any development life cycle: it is safe to say that security can be (and has to be!) performed in any situation. 

Waterfall methodologies used to be popular before the beginning of the 21st century. The most famous application is called the "V model", where phases are performed in sequence and where it is only possible to go backwards by a single step.
In this model, testing activities happen in sequence and are performed as a whole, mostly at the moment of the life cycle when most of the app has already been developed. This means that, in case defects are identified, code may be changed, but it is hardly possible to change the architecture as well as other items put in place at the beginning of the project.

##### Security Testing in Agile / DevOps and DevSecOps

Automation is key in DevSecOps: as stated earlier, the frequency of deliveries from development to operations increase when compared to the traditional approach, and activities that usually require time need to keep up, e.g. deliver the same added value while taking less time. Consequently, unproductive activities need to be removed and essential tasks need to be fastened. This impacts infrastructure changes, deployment and security:
- infrastructure is more and more moving towards **Infrastructure as Code**;
- deployment is more and more scripted, translated through two concepts: **Continuous Integration** and **Continuous Delivery**;
- **security activities** are automated as much as possible and take place all along the lifecycle.

The sections below provide more details about these three points.

###### Infrastructure as Code

Instead of manually provisioning computing resources (physical servers, virtual machines, ...) and modifying configuration files, Infrastructure as Code makes heavy use of tools and automation to fasten the provisioning process and make it more reliable and repeatable. Often, corresponding scripts are stored under version control to facilitate sharing and issue tracking and fixing. 

Such practices facilitate the collaboration between development and operations teams: 
- Devs better understand infrastructure through a point of view that is familiar to them and can prepare resources that will be required by the running application, 
- while Ops operate an environment that better suits the application and share a common language with Devs.

It also facilitates the construction of the different environments required in a classical software creation project, for **development** ("DEV"), **integration** ("INT"), **testing** ("PPR" for Pre-Production) and **production** ("PRD"), the value of infrastructure as code being that these environments can be very similar (ideally, they should be the same).
Note on "PPR": Some tests are usually performed in earlier environments, and tests in PPR are mostly about non-regression and performance with similar data as in production.

Infrastructure as Code is very commonplace in projects using resources in the Cloud, as many vendors provide APIs that can be used by project teams to provision items (virtual machines, storage spaces, ...) and work on configurations (modify memory sizes or the number of CPUs used in virtual machines, ...) instead of having administrators perform these same activities from monitoring consoles.

The main tools used in this domain are Puppet ([Puppet](https://puppet.com/ "Puppet")) and Chef ([Chef](https://www.chef.io/chef/ "Chef")).

###### Deployment

Depending on the maturity of the project organization or the development team, the deployment pipeline can be very sophisticated. In its simplest form, the deployment pipeline consists of a commit phase. The commit phase commonly runs simple compiler checks, the unit test suite, as well as creates a deployable artifact of the application which is called "release candidate". A release candidate is the latest version of changes that has been placed into the trunk of the version control system and will be further evaluated by the deployment pipeline to verify if it is in line with the established standards to be potentially deployed to production.

The commit phase is designed to provide instant feedback to developers and as such is run on every commit to the trunk. Because of that, certain time constraints exist. Typically, the commit phase should run within five minutes, but in any case, shouldn't take longer than 10 minutes to complete. This time constraint is quite challenging in the security context, as many of the currently existing tools can't run in that short amount of time (#paul, #mcgraw).

At this point, an interesting concept needs to be discussed: the reader will often hear about "CI / CD". CI / CD means "Continuous Integration / Continuous Delivery" in some contexts, "Continuous Integration / Continuous Deployment" in some others. Actually, the logic is :
- in Continuous Integration, a build action (triggered either by a commit or performed regularly, every 30 minutes for instance) takes all source code and builds a release candidate. Then, tests can be performed and the compliance of the release with pre-defined rules (for security, quality, ...) can be checked. In case compliance is confirmed, the process can move to the next step; otherwise, the development team needs to take appropriate actions to remediate to the issue(s) and propose changes.
- in Continuous Delivery, the release candidate can move up to the pre-production environment. Then, validation of this release can be performed (either manually or automatically); if the light goes green, deployment can go on. If not, the project team is notified and proper action(s) need(s) to be taken.
- in Continuous Deployment, the release is directly transitioned from integration to production, e.g. it becomes accessible to the user. However, it is strongly advised that no release should reach the production environment when significant defects have been identified during previous activities.

Sometimes, when dealing with applications with a low or medium sensitivity, delivery and deployment may be merged in a single step, where no validation is performed after delivery. However, it is strongly advised to keep these two actions separate and have strong validation when dealing with sensitive applications.

###### Security

At this point, the big question becomes: now that other activities implied in delivering code have significantly improved in terms of speed and effectiveness, how can security keep up? How can we maintain an appropriate level of security? For sure, it would not be a totally good news to be able to deliver value to users more often, but with a lower level of security!

Well, again, the answer comes through the concepts of automation and tooling: by implementing these two concepts all along the project lifecycle, security can be kept at the same level as in the past, and even improved. Also, the higher the expected security level, the more controls, checkpoints and emphasis will take place: for instance,
- Static Application Security Testing (SAST) can take place during the development phase and can be integrated in the Continuous Integration process, with more or less emphasis on scan results; also, more or less demanding Secure Coding Rules can be put in place and their effective implementation checked by SAST tools;
- Dynamic Application Security Testing (DAST) may be automatically performed after the application has been built (e.g. after Continuous Integration has taken place) and before delivery, again with more or less emphasis on results;
- Manual validation checkpoints may be added between two consecutive phases, for instance between delivery and deployment. 

However, in DevOps, the security of an application shall not be seen only during the development phase, but must also be considered during operations: for instance,
- regular scanning should take place (both at the infrastructure and the application levels);
- pentesting may take place regularly (actually, pentesting should be performed on the version of the application used in production, with data similar to the one in production, but in a dedicated environment. Refer to the section on Penetration Testing above for more details);
- active monitoring should be performed in order to identify any issue and remediate it as soon as possible thanks to the feedback loop.

The level of security of a DevSecOps process shall always be under the responsibility of the reader. However, to provide some guidance and for clarity, here is an example of a process:

![Example of a DevSecOps process](Images/Chapters/0x04b/ExampleOfADevSecOpsProcess.jpg)

### References

- [paul] - M. Paul. Official (ISC)2 Guide to the CSSLP CBK, Second Edition ((ISC)2 Press), 2014
- [mcgraw] - G McGraw. Software Security: Building Security In, 2006

