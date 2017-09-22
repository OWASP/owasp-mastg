## Mobile App Security Testing

Throughout the guide, we use "mobile app security testing" as a catch-all phrase for evaluating the security of mobile apps using static and dynamic analysis. In practice, you'll find that various terms such as "mobile app penetration testing", "mobile app security review", and others are used somewhat inconsistently in the security industry, but those terms refer to roughly the same thing. Usually, a mobile app security test is done as part of a larger security assessment or penetration test that also encompasses the overall client-server architecture, as well as server-side APIs used by the mobile app.

In this guide we cover mobile app security testing in two different contexts. The first one is the "classical" security test done towards the end of the development life cycle. Here, the tester gets access to a near-final or production-ready version of the app, identifies security issues, and writes a (usually devastating) report. The other context is implementing requirements and automating security tests from the beginning of the software development life cycle. In both cases, the same basic requirements and test cases apply, but there's a difference in the high-level methodology and level of interaction with the client.

### Principles of Testing

#### White-box Versus Black-box Testing

Let's start by defining the concepts:
- black-box testing is a kind of testing where no knowledge about the app under test is given to the tester. This is sometimes called "zero-knowledge testing". The main interest of this kind of tests is to behave like a real attacker and see what is possible when using publically available or discoverable information.
- white-box testing is the total opposite of black-box testing in that, in this situation, full knowledge about the app is given to the tester: that may include source code, documentations, diagrams, ... While testing in such conditions is way easier and faster than in black-box conditions, it does not allow the checking of as many test cases as black-box. It is generally more purposeful for improving the app against internal attackers. This is sometimes referred to as "full knowledge testing".
- all kinds of testing in between the two previous kinds of tests are called grey-box testing: this is when some information is provided to the tester, but some other is left to find. This is an interesting compromise when it comes to the number of test cases checked, cost, speed and depth of testing. This is the more frequent kind of testing used in the industry.

In order to spend the allocated time for tests as efficiently as possible for a mobile security test, it is strongly advised to request the source code to support testing. Obviously this does not really represent the scenario of an external attacker but this so called white-box testing will make it much easier to identify vulnerabilities, as every anomaly or suspicious behavior you identify can be verified on the code level. Especially if the app is tested the first time a white-box test is the way to go.

Even though decompiling is straightforward on Android, the source code might be obfuscated, which will be time-consuming or even not possible to de-obfuscate in the time you have. Therefore, again the source code should be provided to be able to focus on the overall security of the app.

Black-box testing might still be requested by the client, but it should be made clear that an external attacker always has as much time as he wants and not only a limited time frame as you. Therefore, black-box testing might be a good choice if the app is already mature from a security point of view and if the client wants to test the implemented security controls and their effectiveness.

#### Static versus Dynamic Analysis

On the one hand, Static Analysis deals with examining the inner elements of an application without executing it. It often refers to source code analysis, either done manually or aided by an automated tool. Sometimes, it can be close to white-box testing.
OWASP provides great resources on [Static Code Analysis](https://www.owasp.org/index.php/Static_Code_Analysis "OWASP Static Code Analysis") which can help in understanding the techniques to be used, its strengths and weaknesses and its limitations.

On the other hand, Dynamic Analysis deals with examining the app from the outside when executing it. It can be either manual or automatic. It usually does not provide the same information as Static Analysis and is a good manner to detect interesting elements (assets, features, entry points, ...) with a user point of view. Sometimes, it can be close to black-box testing.
OWASP provides great resources on [Dynamic Analysis](https://www.owasp.org/index.php/Dynamic_Analysis "OWASP Dynamic Analysis") which can help in understanding the different ways to analyse an app.

Now that we have defined what static and dynamic analysis are, let's deep dive shortly and see what each kind of analysis are.

#### Vulnerability Analysis

Vulnerability analysis is, generally speaking, the fact of looking for vulnerabilities in an app. While this may be done manually, most of the time automated scanners are used to identify the main vulnerabilities of an app. Static and dynamic analysis are ways to run vulnerability analysis.

#### Static Analysis

When executing static analysis, the source code of the mobile app is analyzed to ensure sufficient and correct implementation of security controls. In most cases, a hybrid automatic / manual approach is used. Automatic scans catch the low-hanging fruits, while the human tester can explore the code base with specific business and usage contexts in mind, providing enhanced relevance and coverage.

##### Manual Code Analysis

In manual code analysis, a human reviewer manually analyzes the source code of the mobile application for security vulnerabilities. Methods range from a basic keyword search with the 'grep' command to identify usages of potentially vulnerable code patterns, to detailed line-by-line reading of the source code. IDEs (Integrated Development Environments) often provide basic code review functionalities and can be extended through different tools to assist in the reviewing process.

A common approach is to identify key indicators of security vulnerabilities by searching for certain APIs and keywords. For example, database-related method calls like "executeStatement" or "executeQuery" are key indicators which may be of interest. Code locations containing these strings are good starting points for manual analysis.

Compared to automatic code analysis tools, manual code review excels at identifying vulnerabilities in the business logic, standards violations and design flaws, especially in situations where the code is technically secure but logically flawed. Such scenarios are unlikely to be detected by any automatic code analysis tool.

A manual code review requires an expert human code reviewer who is proficient in both the language and the frameworks used in the mobile application. Full code review can be time-consuming, slow and tedious for the reviewer, especially for large code bases with many dependencies.

##### Automatic Code Analysis

In order to fasten the review process, automated analysis tools can be used for Static Application Security Testing (SAST). They check the source code for compliance with a predefined set of rules or industry best practices. The tool then typically displays a list of findings or warnings and flags all detected violations. Static analysis tools come in different varieties - some only run against the compiled app, some need to be fed with the original source code, and some run as live-analysis plugins in the Integrated Development Environment (IDE).

While some static code analysis tools do encapsulate a deep knowledge of the underlying rules and semantics required to perform analysis of mobile apps, they can produce a high number of false positives, particularly if the tool is not properly configured for the target environment. The results must therefore always be reviewed by a security professional.

A list of static analysis tools can be found in the chapter "Testing tools".

#### Dynamic Analysis

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


#### Avoiding False Positives

The challenge with automated testing is that, often, tools are not aware of the context of an app. Consequently, these tools may identify a potential issue that is not one in the given situation. These are called 'False positives'.

For instance, a common pitfall for security testers is reporting issues that would be exploitable in a web browser, but aren't relevant in the context of the mobile app. The reason for this is that automated tools used to scan the back-end service assume a regular, browser based web application. Issues such as CSRF, missing security headers and others are reported accordingly.

Let's take CSRF as an example: a successful CSRF attack requires the following:

1. It must be possible to entice the logged-in user to open a malicious link in the same web browser used to access the vulnerable site;
2. The client (browser) must automatically add the session cookie or other authentication token to the request.

Mobile apps don't fulfill these requirements: even if Webviews and cookie-based session management were used, any malicious link clicked by the user would open in the default browser which has its own, separate cookie store.

Stored Cross-Site Scripting (CSS) can be an issue when the app uses Webviews, and potentially even lead to command execution if the app exports JavaScript interfaces. However, reflected cross-site scripting is rarely an issue for the same reasons stated above (even though one could argue that they shouldn't exist either way - escaping output is simply a best practice that should always be followed).

In any case, think about the actual exploit scenarios and impacts of the vulnerability when performing the risk assessment - don't blindly trust the output of your scanning tool.


#### Penetration Testing (a.k.a. Pentesting)

The classical approach is to perform all-around security testing of the mobile app and its environment on the final or near-final build of the app, e.g. at the end of the development process. In that case, we recommend using the [Mobile App Security Verification Standard (MASVS)](https://github.com/OWASP/owasp-masvs "OWASP MASVS") and the associated checklist as a reference. A typical security test is structured as follows:

- **Preparation** - defining the scope of security testing, such as which security controls are applicable, what goals the development team and organization have for the testing, and what has been identified as sensitive data in the context of the test. More generally speaking, it includes all activities to synchronize with the client and legally protect the tester (often a third-party) for the activities to come. (remember, attacking a system without proper written authorization is illegal in many parts of the world!).
- **Intelligence Gathering** - involves analyzing the **environmental** and **architectural** context of the app, to gain a general contextual understanding of the app.
- **Mapping the Application** - takes as input information from the previous phases; may be complemented by scanning with automated tools and manually playing with the app. This gives a quite thorough understanding of the app, its entry points, the data it holds and give an idea of the main potential vulnerabilities. These vulnerabilities can then be ranked by order of severity and therefore gives the security tester a prioritized list of items he should start with. Produces test cases that may be used during test execution.
- **Exploitation** - this is the phase when the security tester tries to penetrate the app by using the vulnerabilities identified during the previous phase using security tools and techniques. This phase is needed to confirm whether vulnerabilities are real (true positives) or do not lead to any compromise (false positives).
- **Reporting** - essential to the client, this is the moment when the security tester writes a report to list the vulnerabilities he has been able to exploit and document the kind of compromise he has been able to perform and its scope (for instance, which data he has been able to get access to illegitimately). 

##### Preparation

Before conducting a test, an agreement must be reached as to what security level will be used to test the app against. The security requirements should ideally have been decided at the beginning of the project, but this may not always be the case. In addition, different organizations have different security needs, and different amounts of resources to invest in test activities. While the controls in MASVS Level 1 (L1) are applicable to all mobile apps, it is a good idea to walk through the entire checklist of L1 and Level 2 (L2) MASVS controls with technical and business stakeholders to agree on an appropriate level of test coverage.

Organizations / applications may have different regulatory and legal obligations in certain territories. Even if an app does not handle sensitive data, it may be important to consider whether some L2 requirements may be relevant due to industry regulations or local laws. For example, 2-factor authentication (2FA) may be obligatory for a financial app, as enforced by the respective country central bank and / or financial regulatory authorities.

Security goals / controls defined earlier in the development process may also be reviewed during the discussion with stakeholders. Some controls may conform to MASVS controls, but others may be specific to the organization or application.

![Preparation](Images/Chapters/0x03/mstg-preparation.png)

All involved parties need to agree on the decisions made and on the scope in the checklist, as this will define the baseline for all security testing, regardless if done manually or automatically.

###### Coordinating with the Client

Setting up a working testing environment can be a challenging task. For instance, when performing testing on-site at client premises, the restrictions on the enterprise wireless access points and networks may make dynamic analysis more difficult. Company policies may prohibit the use of rooted phones or network testing tools (hardware and software) within the enterprise networks. Apps implementing root detection and other reverse engineering countermeasures may add a significant amount of extra work before further analysis can be performed.

Security testing involves many invasive tasks such as monitoring and manipulating the network traffic between the mobile app and its remote endpoints, inspecting the app data files, and instrumenting API calls. Security controls like certificate pinning and root detection might impede these tasks and slow down testing dramatically.

To overcome these obstacles, it might make sense to request two build variants of the app from the development team. One variant should be provided as a release build to check if the implemented controls like certificate pinning are working properly or can easily be bypassed. The second variant should also be provided as a debug build that deactivates certain security controls. This approach makes it possible to cover all scenarios and test cases in the most efficient way.

Of course, depending on the scope of the engagement, such approach may not be possible. For a white-box test, requesting both production and debug builds will help to go through all test cases and give a clear statement of the security maturity of the app. For a black-box test, the client might prefer the test to be focused on the production app, with the goal of evaluating the effectiveness of its security controls.

For both types of testing engagements, the scope should be discussed during the preparation phase. For example, it should be decided whether the security controls should be adjusted or not. Additional topics to cover are discussed below.

###### Identifying Sensitive Data

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

##### Intelligence Gathering

Intelligence gathering involves the collection of information about the architecture of the app, the business use cases it serves, and the context in which it operates. Such information may be broadly divided into "environmental" and "architectural".

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

##### Mapping the Application

Now that the security tester has information on the nature of the app and its context, the next step is to map its structure and content, e.g. identify its entry points, the features it contains, the data is holds and all other interesting elements to be targeted. 

When penetration testing is performed in a white-box or grey-box manner, all documents from the interior of the project may greatly help and fasten the process: architecture diagrams, functional specifications, code, ... In case source code is available, using SAST tools can reveal valuable information concerning vulnerabilities (SQL Injection, ...). 
When working in black-box mode, DAST tools may provide support and automatically scan the app: when a tester will need hours or days, a scanner may need only a few minutes to perform the same task. However, an important point is that automatic tools still have limitations and will only find what they have been programmed for. As such, human analysis may be needed to add to results from automatic tools (intuition is often key in security testing). 

An artifact to be mentioned is Threat Modeling: when documents from the workshop are available, they usually provide great support in identifying much information a security tester needs (entry points, assets, vulnerabilities, severity, ...). It is strongly advised to discuss the availability of such documents with the client. Threat modeling should be a key part of the software development life cycle and generally happens in the early steps of a project.

The [threat modeling guidelines defined by OWASP](https://www.owasp.org/index.php/Application_Threat_Modeling "OWASP Application Threat Modeling") are generally applicable to mobile apps.

##### Exploitation

Unfortunately, due to shortage of time or limited financial resources, many pentests are limited to mapping the application, often using automated scanners (for instance, for vulnerability analysis). While vulnerabilities identified during the previous phase may be interesting, the reality of their effectiveness need to be confirmed on five axes:
- **Damage potential** - the damage(s) to which the vulnerability can lead if exploited successfully,
- **Reproducibility** - how easy it is to reproduce the attack,
- **Exploitability** - how easy it is to perform the attack,
- **Affected users** - how many users are affected by the attack,
- **Discoverability** - how easy it is to discover the vulnerability.

Indeed, against all odds, some vulnerabilities may not be exploitable and may not lead to any compromise or lead to minor ones. In the opposite manner, some others vulnerabilities may seem harmless at first sight while the tester may find them highly dangerous for the application when testing in real conditions. Performing the exploitation phase with care really brings value to a pentest campaign by characterizing vulnerabilities and proving information on their impacts.


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


### Security Testing and the SDLC

Even if the principles of security testing have not fundamentally changed in recent history, the way to develop software has changed dramatically on its side. While software development was becoming quicker with the wide adoption of Agile practices, security testing had to keep up and to become more agile and quicker, while still providing a high degree of confidence in delivered software.

The following section will focus on this evolution and will provide elements on modern ways security testing is performed.


#### Security Testing in the Software Development Life Cycle

The history of software development is not that old after all, and it is easy to see that, rapidly, teams have stopped developing programs without any framework: we have all experienced the fact that, as the number of lines of code grows, a minimal set of rules are needed in order to keep work under control, meet deadlines, quality and budgets.

In the past, the most widely adopted methodologies were from the "Waterfall" family: development was done from a starting point to a final one, going through several steps, each of them happening one after the other in a predefined sequence. In case something was wrong during a given phase and something had to be changed in a former phase, it was possible to go only one step backward. This was a serious drawback of Waterfall methodologies. Even if they have strong positive points (bring structure, clarify where to put effort, clear and easy to understand, ...), they also have negative ones (creation of silos, slow, specialized teams, ...).

As time was passing and software development was maturing, also competition was getting stronger and stronger, and a need to react faster to market changes while creating software products with smaller budgets rose. The idea of having less structure became popular, with smaller teams collaborating together, breaking silos through the organization from marketing to production. Along with the introduction of Lean practices in software development, the "Agile" concept was born (well-known examples of Agile implementations are Scrum, XP and RAD), which was enabling more autonomous teams to work together in a faster manner.

Originally, security was not an integral part of software development. It was seen as an afterthought, and was performed by Operation teams at the network level: those teams had to find ways to compensate for poor security in software programs! However, while this was possible when software programs were located inside a perimeter, the concept became obsolete as new ways to consume software emerged with Web, Mobile and IoT technologies. Nowadays, security has to be baked **inside** software as it is often very hard in this new paradigm to compensate for existing vulnerabilities.

The way to incorporate security during software development is to put in place a Secure SDLC (Software Development Life Cycle). A Secure SDLC does not depend on any methodology nor on any language, and it is possible to incorporate one in Waterfall or Agile: no excuse not to use one! This chapter will focus on Agile and Secure SDLC, in particular in the DevOps world. The reader will find below details on state-of-the-art ways to develop and deliver secure software in a fast-paced and collaborative manner that promotes autonomy and automation.

Note: SDLC will be used interchangeably with Secure SDLC in the coming paragraphs, e.g. the assumption that security is part of a software development process needs to become natural to the reader. 
Also, in the same spirit, DevSecOps is the name used when there is a need to emphasize the fact that security is part of DevOps. However, we'll assume that security is naturally part of DevOps!

#### SDLC Overview

##### General Description of SDLC

Whatever the development methodology that is being used, a SDLC always follows the same process (either sequentially in Waterfall or iteratively in Agile):

- Perform a **risk assessment** of the application and its components to identify their respective risk profiles. These risk profiles typically depend on the risk appetite of the organization and the regulatory requirements for the application under consideration. The risk assessment is additionally influenced by other factors such as whether the application is accessible from the Internet, or what kind of data is processed and stored. All sorts of risks need to be taken into account : financial, marketing, industrial, ... If available, a data classification policy determines which data is considered sensitive and prescribes how this data has to be secured;
- At the beginning of a project or a development cycle, at the same time when functional requirements are gathered, **Security Requirements** are listed and clarified. As use cases are built, **Abuse Cases** are added. Teams (including development teams) may be trained on security if needed (Secure Coding, ...). 
For mobile applications, the [OWASP MASVS](https://www.owasp.org/images/f/fe/MASVS_v0.9.3.pdf "OWASP MASVS") can be leveraged to determine the security requirements based on the risk assessment that was conducted in this initial step. It is common, especially for agile projects, to iteratively review the set of requirements based on newly added features and new classes of data that is handled by the application;
- Then, as architecture and design are ongoing, a foundational artifact must be performed: **Threat Modeling**, which is basically an activity where threats are identified, enumerated, prioritized and their treatment initialized. An input of the Threat Model is the **Security Architecture**, but which can be refined after Threat Modeling (both for software and hardware aspects). **Secure Coding rules** are established and the list of **Security tools** that will be used is created. Also, the strategy for **Security testing** is clarified;
- All security requirements and design considerations should be stored in the Application Life cycle Management System (ALM), which is typically known as issue tracker, that the development / ops team already uses to ensure that security requirements are tightly integrated into the development workflow. The security requirements should ideally also contain the relevant source code snippets for the used programming language, to ensure that developers can quickly reference them. Another strategy for secure coding guidelines is to create a dedicated repository under version control, that only contains these code snippets, which has many benefits over the traditional approach of storing these guidelines in word documents or PDFs.
- The next step is to **securely develop software**. In order to improve the security level of produced code, some security activities need to be performed, including **Security Code Reviews**, **Security Static Analysis** and **Security Unit Testing**. While these activities have their equivalents for quality, the same logic needs to be applied for security, e.g. reviewing, analyzing and testing code for security defects (for instance, missing validation of inputs, failing to free all resources, ...);
- Then comes the long-awaited moment to perform tests on the release candidate: **Penetration Testing** ("Pentests"), using both manual and automated techniques;
- And finally, after software has been **Accredited** by all stakeholders, it can be transitioned to Operation teams and safely put in Production.

The picture below shows all the phases with the different artifacts:
-- TODO [Add a picture of a SDLC diagram that clarifies the description above] --

Based on the general risk profile of the project, some artifacts may be simplified (or even skipped) while others may be added (formal intermediary approvals, formal documentation of certain points, ...). **Always keep in mind a SDLC is meant to bring risk reduction to software development and is a framework that helps put in place controls that will reduce those risks to an acceptable level.** While this is a generic description of SDLC, always tailor this framework to the needs of your projects.


##### Defining a Test Strategy

The purpose of a test strategy is to define which tests will be performed all along the SDLC and how often. Its goal is to make sure security objectives are met by the final software product, which are generally expressed by customers / legal / marketing / corporate teams, while being cost-effective. 
The test strategy is generally created at the beginning of a project, after risks have been clarified (Initiation phase) but before code development (Coding phase) starts. It generally takes place during the Architecture and Design phase. It takes inputs from activities such as Risk Management, Threat Modeling, Security Engineering, etc.

-- TODO [Add diagram (in the form of a workflow) showing inputs of a Test Strategy, and outputs (test cases, ...)] --

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

It is important to distinguish between two kinds of tests: tests performed by an internal team and tests performed by an independant third-party. Generally speaking, internal tests are useful to improve daily operations, while third-part tests are more beneficial to the whole organization. However, internal tests can be performed quite often when third-party tests happen once or twice a year at best; also, the first kind are less expensive while the other one requires a significant budget. 
Both are needed, and many regulations mandate tests from an independant third-party as they can be more trusted.

#### Security Testing in Waterfall

##### What Waterfall is and how testing activities are arranged

Basically, SDLC does not mandate the use of any development lifecycle: it is safe to say that security can be (and has to be!) performed in any situation. 

Waterfall methodologies used to be popular before the beginning of the 21st century. The most famous application is called the "V model", where phases are performed in sequence and where it is only possible to go backwards by a single step.
In this model, testing activities happen in sequence and are performed as a whole, mostly at the moment of the lifecycle when most of the app has already been developed. This means that, in case defects are identified, code may be changed, but it is hardly possible to change the architecture as well as other items put in place at the beginning of the project.

#### Security Testing in Agile / DevOps and DevSecOps

DevOps refers to practices that focus on a close collaboration between all stakeholders involved in delivering software. DevOps is the logical evolution of Agile in that it enables software to be released to users as rapidly as possible. Besides the collaboration aspect, to a large extent, this is facilitated through heavy automation of the build, test and release process of software and infrastructure changes. This automation is embodied in the deployment pipeline.

The term DevOps might be mistaken for only expressing collaboration between development and operations teams, however, as Gene Kim, a DevOps thought leader, puts it: "At first blush, it seems as though the problems are just between dev and ops," he says, "but test is in there, and you have information security objectives, and the need to protect systems and data. These are top-level concerns of management, and they have become part of the DevOps picture."

In other words, when you hear "DevOps" today, you should probably be thinking [DevOpsQATestInfoSec](https://techbeacon.com/evolution-devops-new-thinking-gene-kim "The evolution of DevOps: Gene Kim on getting to continuous delivery").”

Security is just as important for the business success as the overall quality, performance and usability of an application. As development cycles are shortened and deployment frequencies increased it is elementary to ensure that quality and security is built in from the very beginning. DevSecOps is about bringing security in the DevOps process.

From the human aspect, this is achieved by creating cross functional teams that work together on achieving business outcomes. This section is going to focus on the interaction with and integration of security into the development life cycle, from the inception of requirements, all the way until the value of the change is made available to users.

##### What Agile / DevSecOps are and how testing activities are arranged

###### Overview

As the frequency of deployments to production increases, and DevOps high-performers deploy to production many times a day, it is elementary to automate as many of the security verification tasks as possible. The best approach to facilitate that is by integrating security into the deployment pipeline. A deployment pipeline is a combination of continuous integration and continuous delivery practices, which have been created to facilitate rapid development and receive almost instantaneous feedback upon every commit. More details on the deployment pipeline are provided in the section below.

###### The Deployment Pipeline

Depending on the maturity of the project organization or the development team, the deployment pipeline can be very sophisticated. In its simplest form, the deployment pipeline consists of a commit phase. The commit phase commonly runs simple compiler checks, the unit test suite, as well as creates a deployable artifact of the application which is called release candidate. A release candidate is the latest version of changes that has been checked into the trunk of the version control system and will be evaluated by the deployment pipeline to verify if it is in line with the established standards to be potentially deployed to production.

The commit phase is designed to provide instant feedback to developers and as such is run on every commit to the trunk. Because of that, certain time constraints exist. Typically, the commit phase should run within five minutes, but in any case, shouldn't take longer than 10 minutes to complete. This time constraint is quite challenging in the security context, as many of the currently existing tools can't run in that short amount of time (#manoranjan, #mcgraw).


### References

- [paul] - M. Paul. Official (ISC)2 Guide to the CSSLP CBK, Second Edition ((ISC)2 Press), 2014
- [mcgraw] - G McGraw. Software Security: Building Security In, 2006



