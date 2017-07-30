## Mobile App Security Testing

Throughout the guide, we use "mobile app security testing" as an catch-all phrase for evaluating the security of mobile apps using static and/or dynamic analysis. In practice you'll find that various terms such as "Mobile App Penetration Testing", "Mobile App Security Review", and others are used somewhat inconsistently in the security industry, but those terms refer to roughly the same thing. Usually, a mobile app security test is done as part of a larger security assessment or penetration test that also encompasses the overall client-server architecture, as well as server-side APIs used by the mobile app.

In this guide we cover mobile app security testing in two different contexts. The first one is the "classical" security test done towards the end of the development life cycle. Here, the tester gets access to a near-final or production-ready version of the app, identifies security issues, and writes an (usually devastating) report. The other context is implementing requirements and automating security tests from the beginning of the software development life cycle. In both cases, the same basic requirements and test cases apply, but there's a difference in the high-level methodology and level of interaction with the client.

### Security Testing the Old-School Way

The classical approach is to perform all-around security testing of the mobile app and its environment on the final or near-final build of the app. In that case, we recommend using the [Mobile App Security Verification Standard (MASVS)](https://github.com/OWASP/owasp-masvs "OWASP MASVS") and checklist as a reference. A typical security test is structured as follows.

- **Preparation** - defining the scope of security testing, such as which security controls are applicable, what goals the development team/organization have for the testing, and what counts as sensitive data in the context of the test.
- **Intelligence Gathering** - involves analyzing the **environmental** and **architectural** context of the app, to gain a general contextual understanding of the app.
- **Threat Modeling** - consumes information gathered during the earlier phases to determine what threats are the most likely, or the most serious, and therefore which should receive the most attention from a security tester. Produces test cases that may be used during test execution.
- **Vulnerability Analysis** - identifies vulnerabilities using the previously created test cases, including static, dynamic and forensic methodologies.

#### Preparation

Before conducting a test, an agreement must be reached as to what security level will be used to test the app against. The security requirements should ideally have been decided at the beginning of the SDLC, but this may not always be the case. In addition, different organizations have different security needs, and different amounts of resources to invest in test activity. While the controls in MASVS Level 1 (L1) are applicable to all mobile apps, it is a good idea to walk through the entire checklist of L1 and Level 2 (L2) MASVS controls with technical and business stakeholders to agree an appropriate level of test coverage.

Organizations/applications may have different regulatory and legal obligations in certain territories. Even if an app does not handle sensitive data, it may be important to consider whether some L2 requirements may be relevant due to industry regulations or local laws. For example, 2-factor-authentication (2FA) may be obligatory for a financial app, as enforced by the respective country's central bank and/or financial regulatory authority.

Security goals/controls defined earlier in the SDLC may also be reviewed during the stakeholder discussion. Some controls may conform to MASVS controls, but others may be specific to the organization or application.

![Preparation](Images/Chapters/0x03/mstg-preparation.png)

All involved parties need to agree on the decisions made and on the scope in the checklist, as this will define the baseline for all security testing, regardless if done manually or automatically.

##### Identifying Sensitive Data

Classification of sensitive information can vary between different industries and countries. Beyond legal and civic obligations, organizations may take a more restrictive view of what counts as sensitive data, and may have a data classification policy that clearly defines what counts as sensitive information.

There are three general states in which data may be accessible:

- **At rest** - when the data is sitting in a file or data store
- **In use** - when an application has load the data into its address space
- **In transit** - when data has been sent between consuming process - e.g. during IPC.

The degree of scrutiny to apply to each state may depend on the criticality of the data, and likelihood of access. For example, because the likelihood of malicious actors gaining physical access to mobile devices is greater, data held in application memory may be more at risk of being accessed via core dumps than that on a web-server.

If no data classification policy is available, the following kinds of information are generally considered to be sensitive:

- User authentication information (credentials, PINs etc.).
- Personal Identifiable Information (PII) that can be abused for identity theft: Social security numbers, credit card numbers, bank account numbers or health information.
- Device identifiers that might allow to identity a person.
- Highly sensitive data that would lead to reputational harm and/or financial costs if compromised.
- Any data that must be protected by law or for compliance reasons.
- Finally any technical data, generated by the application or it's related systems, that is used to protect other data or the system, should also be considered as sensitive information (e.g. encryption keys).

It may be impossible to detect leakage of sensitive data without a firm definition of what counts as such, so such a definition must be agreed upon in advance of testing.

#### Intelligence Gathering

Intelligence gathering involves the collection of information about the architecture of the app, the business use cases it serves, and the context in which it operates. Such information may be broadly divided into "environmental" and "architectural".

##### Environmental Information

Environmental information concerns understanding:

- The goals the organization has for the app. What the app is supposed to do shapes the ways users are likely to interact with it, and may make some surfaces more likely to be targeted than others by attackers.   
- The industry in which they operates. Specific industries may have differing risk profiles, and may be more or less exposed to particular attack vectors.
- Stakeholders and investors. Understanding who is interested in and responsible for the app.
- Internal processes, workflows and organizational structures. Organization-specific internal processes and workflows may create opportunities for [business logic exploits](https://www.owasp.org/index.php/Testing_for_business_logic "Testing business logic").

##### Architectural Information

Architectural information concerns understanding:

- The mobile app: How the app accesses data and manages it in-process, how it communicates with other resources, manages user sessions, and whether it detects and reacts to running on jailbroken or rooted phones.
- The Operating System: What operating systems and versions does the app run on (e.g. is it restricted to only newer Android or iOS, and do we need to be concerned about vulnerabilities in earlier OS versions), is it expected to run on devices with Mobile Device Management (MDM) controls, and what OS vulnerabilities might be relevant to the app.
- Network: Are secure transport protocols used (e.g. TLS), is network traffic encryption secured with strong keys and cryptographic algorithms (e.g. SHA-2), is certificate pinning used to verify the endpoint, etc.
- Remote Services: What remote services does the app consume? If they were compromised, could the client by compromised?

#### Threat Modeling

Threat Modeling involves using the results of the information gathering phase to determine what threats are likely or severe, producing test cases that may be executed at later stages. Threat modeling should be a key part of the software development life cycle, and ideally be performed at an earlier stage.

The [threat modeling guidelines defined by OWASP](https://www.owasp.org/index.php/Application_Threat_Modeling "OWASP Application Threat Modeling") are generally applicable to mobile apps.

#### Vulnerability Analysis

##### White-box versus Black-box

In order to spent the time you have for a mobile security test as efficient as possible, you should request for the source code to support your testing. Obviously this does not really represent the scenario of an external attacker but this so called white-box testing will make it much easier to identify vulnerabilities, as every anomaly or suspicious behaviour you identify can be verified on the code level. Especially if the app is tested the first time a white-box test should be the way to go.

Even though decompiling is straightforward on Android, the source code might be obfuscated, which will be time consuming or even not possible to de-obfuscate in the time you have. Therefore again the source code should be provided to be able to focus on the overall security of the app.

Black-box testing might still be requested by the client, but it should be made clear that an external attacker always has as much time as he wants and not only a limited time frame as you. Therefore black-box testing might be a good choice if the app is already mature from a security point of view and if the client wants to test the implemented security controls and their effectiveness.

##### Static Analysis

When executing static analysis, the source code of the mobile app is analyzed to ensure sufficient and correct implementation of security controls. In most cases, a hybrid automatic / manual approach is used. Automatic scans catch the low-hanging fruits, while the human tester can explore the code base with specific business and usage contexts in mind, providing enhanced relevance and coverage.

##### Automatic Code Analysis

Automated analysis tools check the source code for compliance with a predefined set of rules or industry best practices. The tool then typically displays a list of findings or warnings and flags all detected violations. Static analysis tools come in different varieties - some only run against the compiled app, some need to be fed with the original source code, and some run as live-analysis plugins in the Integrated Development Environment (IDE).

While some static code analysis tools do encapsulate a deep knowledge of the underlying rules and semantics required to perform analysis of mobile apps, they can produce a high number of false positives, particularly if the tool is not configured properly for the target environment. The results must therefore always be reviewed by a security professional.

A list of static analysis tools can be found in the chapter "Testing tools".

##### Manual Code Analysis

In manual code analysis, a human reviewer manually analyzes the source code of the mobile application for security vulnerabilities. Methods range from a basic keyword search with grep to identify usages of potentially vulnerable code patterns, to detailed line-by-line reading of the source code. IDEs often provide basic code review functionality and can be extended through different tools to assist in the reviewing process.

A common approach is to identify key indicators of security vulnerabilities by searching for certain APIs and keywords. For example, database-related method calls like "executeStatement" or "executeQuery" are key indicators which may be of interest. Code locations containing these strings are good starting points for manual analysis.

Compared to automatic code analysis tools, manual code review excels at identifying vulnerabilities in the business logic, standards violations and design flaws, especially in situations where the code is technically secure but logically flawed. Such scenarios are unlikely to be detected by any automatic code analysis tool.

A manual code review requires an expert human code reviewer who is proficient in both the language and the frameworks used in the mobile application. As full code review can be time-consuming, slow and tedious for the reviewer; especially for large code bases with many dependencies.

##### Dynamic Analysis

In dynamic analysis the focus is on testing and evaluating an app by executing it in real-time. The main objective of dynamic analysis is to find security vulnerabilities or weak spots in a program while it is running. Dynamic analysis is conducted both on the mobile platform layer also be conducted against the backend services and APIs of mobile applications, where its request and response patterns can be analyzed.

Usually, dynamic analysis is performed to check whether there are sufficient security mechanisms in place to prevent disclosure of data in transit, authentication and authorization issues and server configuration errors.

###### Pros of Dynamic Analysis

- Does not require access to the source code
- Able to identify infrastructure, configuration and patch issues that static analysis tools may miss

###### Cons of Dynamic Analysis

- Limited scope of coverage because the mobile application must be foot-printed to identify the specific test area
- No access to the actual instructions being executed, as the tool exercises the mobile application and conducts pattern matching on requests and responses

##### Runtime Analysis

<!-- TODO [Describe Runtime Analysis : goal, how it works, kind of issues that can be found] -->

#### Reporting

<!--TODO -->

##### Avoiding False Positives

A common pitfall for security testers is reporting issues that would be exploitable in a web browser, but aren't relevant in the context of the mobile app. The reason for this is that automated tools used to scan the backend service assume a regular, browser based web application. Issues such as CSRF, missing security headers and others are reported accordingly.

For example, a successful CSRF attack requires the following:

1. It must be possible to entice the logged-in user to open a malicious link in the same web browser used to access the vulnerable site;
2. The client (browser) must automatically add the session cookie or other authentication token to the request.

Mobile apps don't fulfill these requirements: Even if Webviews and cookie-based session management were used, any malicious link clicked by the user would open in the default browser which has its own, separate cookie store.

Stored cross-site Scripting can be an issue when the app uses Webviews, and potentially even lead to command execution if the app exports JavaScript interfaces. However, reflected cross-site scripting is rarely an issue for the same reasons stated above (even though one could argue that they shouldn't exist either way - escaping output is simply a best practice that should always be followed).

In any case, think about the actual exploit scenarios and impacts of the vulnerability when performing the risk assessment - don't blindly trust the output of your scanning tool.

### Modern Security Testing

Even if the principles of security testing have not fundamentaly changed in recent history, the way to develop software has changed on its side: while software development was becoming quicker with the wide adoption of Agile practices, security testing had to keep up and to become more agile and quicker, while still providing a high degree of confidence in delivered software. 

The following section will focus on this evolution and will provide elements on modern ways security testing is performed.

#### Security Testing in the Software Development Life Cycle

The history of software development is not that old after all, and it is easy to see that, rapidly, teams have stopped developing programs without any framework: we have all experienced the fact that, as the number of lines of code grows, a minimal set of rules are needed in order to keep work under control, meet deadlines, quality and budgets.

In the past, the most widely adopted methodologies were from the "Waterfall" family: development was done from a starting point to a final one, going through several steps, each of them happening one after the other in a predefined sequence. In case something was wrong during a given phase and something had to be changed in a former phase, it was possible to go only one step backward. This was a serious drawback of Waterfall methodologies. Even if they have strong positive points (bring structure, clarify where to put effort, clear and easy to understand, ...), they also have negative ones (creation of silos, slow, specialized teams, ...).

As time was passing and software development was maturing, also competition was getting stronger and stronger, and a need to react faster to market changes while creating software products with smaller budgets rose. The idea of having fewer structure with smaller teams collaborating together, breaking silos through the organization from marketing to production, became popular. Along with the introduction of Lean practices in software development, the "Agile" concept was born (well known examples of Agile implementations are Scrum, XP and RAD), which was enabling more autonomous teams to work together in a faster manner.

Originally, security was not an integral part of software development. It was seen as an afterthought, and was performed by Operation teams at the network level: those teams had to find ways to compensate for poor security in software programs! However, while this was possible when software programs were located inside a perimeter, the concept became obsolete as new ways to consume software emerged with Web, Mobile and IoT technologies. Nowadays, security has to be baked **inside** software as it is often very hard in this new paradigm to compensate for existing vulnerabilities.

The way to incorporate security during software development is to put in place a Secure SDLC (Software Development Life Cycle). A Secure SDLC does not depend on any methodology nor on any language, and it is possible to incorporate one in Waterfall or Agile: no excuse not to use one! This chapter will focus on Agile and Secure SDLC, in particular in the DevOps world. The reader will find below details on state-of-the-art ways to develop and deliver secure software in a fast-paced and collaborative manner that promotes autonomy and automation.

#### Agile and DevOps

##### DevOps

DevOps refers to practices that focus on a close collaboration between all stakeholders involved in delivering software. DevOps is the logical evolution of Agile in that it enables software to be released to users as rapidly as possible. Besides the collaboration aspect, to a large extent, this is facilitated through heavy automation of the build, test and release process of software and infrastructure changes. This automation is embodied in the deployment pipeline.

###### -- Todo [Add deployment pipeline overview and description specific for mobile apps.] --

The term DevOps might be mistaken for only expressing collaboration between development and operations teams, however, as Gene Kim, a DevOps thought leader, puts it: “At first blush, it seems as though the problems are just between dev and ops," he says, "but test is in there, and you have information security objectives, and the need to protect systems and data. These are top-level concerns of management, and they have become part of the DevOps picture."

In other words, when you hear "DevOps" today, you should probably be thinking [DevOpsQATestInfoSec](https://techbeacon.com/evolution-devops-new-thinking-gene-kim "The evolution of DevOps: Gene Kim on getting to continuous delivery").”

Security is just as important for the business success as the overall quality, performance and usability of an application. As development cycles are shortened and deployment frequencies increased it is elementary to ensure that quality and security is built in from the very beginning.

From the human aspect, this is achieved by creating cross functional teams that work together on achieving business outcomes. This section is going to focus on the interaction with and integration of security into the development life cycle, from the inception of requirements, all the way until the value of the change is made available to users.


#### SDLC Overview

##### General description of SDLC

Whatever the development methodology that is being used, a SDLC always follows the same process:

- Perform a **risk assessment** of the application and its components to identify their risk profile. This risk profile typically depends on the risk appetite of the organization and the regulatory requirements for the application in scope. The risk assessment is additionally influenced by other factors such as whether the application is accessible from the internet, or what kind of data is processed and stored. All sorts of risks need to be taken into account : financial, marketing, industrial, ... A data classification policy determines which data is considered sensitive and prescribes how this data has to be secured.
- At the beginning of a project or a development cycle, at the same time when functional requirements are gathered, **Security Requirements** are listed and clarified. As use cases are built, **Abuse Cases** are added. Teams (including development teams) may be trained on security if needed (Secure Coding, ...);
- For mobile applications, the [OWASP MASVS](https://www.owasp.org/images/f/fe/MASVS_v0.9.3.pdf "OWASP MASVS") can be leveraged to determine the security requirements based on the risk assessment that was conducted in this initial step. It is common, especially for agile projects, to iteratively review the set of requirements based on newly added features and new classes of data that is handled by the application.
- Then, as architecture and design are ongoing, a foundational artefact must be performed: **Threat Modeling**, which is b asically an activity where threats are identified, enumerated, prioritized and their treatment initialized. An input of the Threat Model is the **Security Architecture**, but which can be refined after Threat Modeling (both for software and hardware aspects). **Secure Coding rules** are established and the list of **Security tools** that will be used is created. Also, the strategy for **Security testing** is clarified;
- All security requirements and design considerations should be stored in the Application Life cycle Management System (ALM), which is typically known as issue tracker, that the development/ops team already uses to ensure that security requirements are tightly integrated into the development workflow. The security requirements should ideally also contain the relevant source code snippets for the used programming language, to ensure that developers can quickly reference them. Another strategy for secure coding guidelines is to create a dedicated repository under versioning control, that only contains these code snippets, which has many benefits over the traditional approach of storing these guidelines in word documents or PDFs.
- The next step is to **securely develop software**. In order to improve the security level of produced code, some security activities need to be performed, including **Security Code Reviews**, **Security Static Analysis** and **Security Unit Testing**. While these activities have their equivalents for quality, the same logic needs to be applied for security, e.g. reviewing, analysing and testing code for security defects (for instance, missing validation of inputs, failing to free all resources, ...);
- Then comes the long-awaited moment to perform tests on the release candidate: **Penetration Testing** ("Pentests"), using both manual and automated techniques;
- And finally, after software has been **Accredited** by all stakeholders, it can be transitioned to Operation teams and safely put in Production.

The picture below shows all the phases with the different artefacts:
-- TODO [Add a picture of a SDLC diagram that clarifies the description above] --

Based on the risks of the project, some artefacts may be simplified (or even skipped) while others may be added (formal intermediary approvals, formal documentation of certain points, ...). **Always keep in mind a SDLC is meant to bring risk reduction to software development and is a framework that helps put in place controls that will reduce those risks to an acceptable level.** While this is a generic description of SDLC, always tailor this framework to the needs of your projects.

##### Diving into phases and artefacts

Now, let's have a closer look at the five phases listed above and let's clarify their main purposes, what is done while they take place and who performs them.

###### Initiation phase

This is the first phase of a project, when requirements are gathered from the field and defined for the project. They should include both functional (e.g. what features will be created for the end user) and security (e.g. what security features will need to be implemented to allow end users to trust the software product) requirements. In this phase, all activities that need to happen before technical work starts and all others that can be anticipated will take place. This is also the moment when Proof of Concepts may be done and when the project viability is confirmed. Typically, teams close to business functions such as marketing (marketing people, or product owners, ...), management and finance are involved.

###### Architecture and Design phase

After the project has been confirmed, the technical team will start working on early technical activities that will enable coding teams to be productive. In this matter, risks are analyzed and relevant countermeasures identified and clarified. The architecture and coding approach as well as testing strategies and the appropriate tools are confirmed, and the different environments (e.g. DEV, QA, SIT, UAT, PROD) are created and put in place. This phase is pivotal as its main goal is to go from a non-technical definition of needs to the point where technical teams are ready to give birth to code that will make up the software product. Typically, Architects, Designers, QA teams, Testers and AppSec experts are involved.

###### Coding phase

This is the moment when code is produced and efforts become visible. This may be seen as the most important phase; however, one must keep in mind that all activities happening before and after the current phase are meant to support code creation and make sure it reaches proper standards for quality and security while meeting deadlines and budgets. In this phase, development teams work in the defined environment to implement requirements following previously defined guidelines. The main people who are involved are developers.

###### Testing phase

This is the phase when produced software is tested. As testing can take many forms (see detailed section on Security Testing in the SDLC below), testing activities may be performed during coding (the obvious goal being to discover issues as soon as possible). Depending on organizations, the project risk profile and techniques used, testing teams may be independent from coding teams. The main people involved during this phase are Testers. Test cases should exist that map tightly to the established security requirements and that are ideally presented in a way that allows codification and subsequently automated verification.

###### Release phase

At this point of time, code has been created and tested. Its security level has been assessed; often, metrics are produced to support evidence that code meets the expected level of security. However, it now has to be transitioned to the customer, e.g. it has to be accepted by stakeholders (management, marketing, ...) as able to create value on the market and be of economical interest to customers; next to that, it will be made available to the market. It is not enough to produce secure software, but it now has to be safely transitioned to production environments, which in turn must be secured (both in the short term and in the long term); documentation for operation teams may be created. In this phase, stakeholders (management, marketing, ...) are first involved, as well as technical teams (testing, operations, quality, ...).


Even if the previous description seems to be "Waterfall-like", it also applies to Agile methodologies: the same logic is used, but in a more iterative manner. Some activities may be done only once (for instance project initiation), however smaller parts of similar activities will happen regularly all along the project (like bringing new requirements into light and clarifying them into user stories). In the same manner, testing will not happen only once at the end of a project, but, on each iteration, tests will focus on the amount of code that was produced in the iteration. This in-cycle testing is preferred over the out-of-cycle approach, because the longer it takes for developers to receive feedback, the more time it will take them to make the context switch.

#### Security Testing in the SDLC

##### Overview

A well-known statement in software development (and many other fields as well) is that the sooner tests take place, the easier and more cost-effective it is to fix a defect. The same applies to defects related to cyber security: identifying (and fixing) vulnerabilities early in the development life cycle gives better results when it comes to produce secure software. In some ways, Quality Testing and Security Testing may share common aspects as both are meant to raise customer satisfaction.

Testing can be performed in many forms during the life cycle: using automated tools like Static Analysis, writing Unit Tests as code is being created, running Penetration Tests (either manually or with the help of scanning tools) after software has been developed. However, an emphasis should always be put on planning and preparing these efforts early in the Secure SDLC: a Test Plan should be initiated and developed at the beginning of the project, listing and clarifying the kind of tests that will be executed, their scope, how and when they will take place and with what budget. Also, abuse cases should be written early in the project (ideally at the same time when use cases are created) to provide guidance to test teams all along development. Finally, an artefact that should always be considered is Threat Modeling, which allow teams to focus on the right components in the architecture with the proper tests and proper coverage to ensure that the security controls have been implemented correctly.

The following diagram provides an overview of the way to perform test in the SDLC:

-- TODO [Add diagram to summarize the above paragraph and clarify the way test should be performed (planned, executed and reviewed)] --

##### Different kinds of tests

As stated before, several kinds of tests can be made along the SDLC. According to the risk profile of the targeted software, several kind of tests can be performed:

- **Analysis**: by nature, static analysis is about analysing source code without running it. The goal of this artefact is twofold: make sure the Secure Coding rules the team has agreed on are correctly implemented when writing code, and finding vulnerabilities. Often, specialized software tools are used to automate this task, as hundreds and thousands of lines of code may need to be analyzed. However, the drawback is that tools can only find what they have been told to look for and, today, are not as successful as human beings. This is the reason why sometimes Static Analysis is performed by humans (in addition to tools or not): it may take more time for humans, but they have a more creative way to detect vulnerabilities. Examples of tools for Static Analysis are given in another section.
- **Unit Tests**: unit tests make up the family of tests that are the closest to source code (e.g. they are focused on a single unit) as they are performed along with code. According to the methodology in use, they can be created either before code is developed (known as Test Driven Development (TDD)) or right after. Whatever the case, the end goal is to verify that produced code is behaving as expected, but also that proper controls are put in place to prevent abuse cases (input filtering / validation, whitelisting, ...) and cannot be circumvented. Unit Tests are used to detect issues early in the development life cycle in order to fix them as quickly and effectively as possible. They are different from other forms of tests, like Integration / Verification / Validation tests, and may not be used to detect the same kind of issue. Often, Unit Tests are aided with tools; a few of them are listed in another section.
- **Penetration Testing**: this is the "king" of security tests, the one that is the most famous and often performed. However, one must keep in mind that they happen late in the development life cycle and that they cannot find every kind of flaw. They are too often constrained by available resources (time, money, expertise, ...), and as such should be complemented by other kind of tests. The current guide is about pentesting, and the reader will find a lot of useful information to conduct added-value tests and find even more vulnerabilities. Pentesting techniques include vulnerability scanning and fuzzing; however, Penetration Tests can be much more multi-facetted than these two examples. Useful tools are listed in another section.

A clear difference shall be made between quality testing and security testing: while quality testing is about making sure an explicitly planned feature has been implemented in the proper way, security testing is about making sure that:

- existing features cannot be used in a malicious way
- no new feature has involuntarily been introduced that could endanger the system or its users.

As a consequence, performing one type of tests is not enough to pretend having covered both types and that the produced software is both usable and secure. The same care should be given to both types of tests as they are of the same importance and that final users now put a strong emphasis both on quality (e.g. the fact features that are brought to them perform the way they expect them to) and security (e.g. that they can trust the software vendor that their money will not be stolen or their private life will remain private).

##### Defining a Test Strategy

The purpose of a test strategy is to define which tests will be performed all along the SDLC and how often. Its goal is twofold: make sure security objectives are met by the final software product, which are generally expressed by customers/legal/marketing/corporate teams, while being cost-effective. The test strategy is generally created at the beginning of a project, after risks have been clarified (Initiation phase) but before code production (Coding phase) starts. It generally takes place during the Architecture and Design phase. It takes inputs from activities such as Risk Management, Threat Modeling, Security Engineering, etc.

-- TODO [Add diagram (in the form of a workflow) showing inputs of a Test Strategy, and outputs (test cases, ...)] --

A Test Strategy does not always need to be formally written: it may be described through Stories (in Agile projects), quickly written in the form of checklists, or test cases could be written in a given tool; however, it definitely needs to be shared, as it may be defined by the Architecture team, but will have to be implemented by other teams such as Development, Testing, QA. Moreover, it needs to be agreed upon by all technical teams as it should not place unacceptable burdens on any of them.

Ideally, a Test Strategy addresses topics such as:

- Objectives to be met and description of risks to be put under control.
- How these objectives will be met and risks reduced to an acceptable level: which tests will be mandatory, who will perform them, how, when, and at which frequency.
- Acceptance criteria of the current project.

In order to follow its effectiveness and progress, metrics should be defined, updated all along the project and periodically communicated. An entire book could be written on the relevant metrics to choose; the best that can be said is that they depend on risk profiles, projects and organizations. However, some examples of metrics include:

- The number of stories related to security controls that are implemented,
- Code coverage for unit tests on security controls and sensitive features,
- The number of security bugs found by static analysis tools upon each build,
- The trend of the backlog for security bugs (may be sorted by criticality).

These are only suggestions, and other metrics may be even more relevant in your case. Metrics are really powerful tools to get a project under control, provided they give a clear view and in a timely manner to project managers on what is happening and what needs to be improved to reach targets.

#### Team management

-- TODO [Develop content on Team Management in SDLC] --

- explain the importance of Separation of Duties (developers VS testers, ...)
- internal VS sub-contracted pentests
- state the importance of awareness and training
- give some examples of training (secure coding, ...)

#### Security Testing in DevOps Environments

##### Overview

As the frequency of deployments to production increases, and DevOps high-performers deploy to production many times a day, it is elementary to automated as many of the security verification tasks as possible. The best approach to facilitate that is by integrating security into the deployment pipeline. A deployment pipeline is a combination of continuous integration and continous delivery practices, which have been created to facilitate rapid development and receive almost instantaneous feedback upon every commit. More details on the deployment pipeline are provided in the section below.

##### The Deployment Pipeline

Depending on the maturity of the organisation, or development team, the deployment pipeline can be very sophisticated. In it's simplest form, the deployment pipeline consists of a commit phase. The commit phase commonly runs simple compiler checks, the unit tests suite, as well as creates a deployable artefact of the application which is called release candidate. A release candidate is the latest version of changes that has been checked into the trunk of the versioning control system and will be evaluated by the deployment pipeline to verify if it is in-line with the established standards to be potentially deployed to production.

The commit phase is designed to provide instant feedback to developers and as such is run on every commit to the trunk. Because of that, certain time constraints exists. Typically, the commit phase should run within five minutes, but in any case, shouldn't take longer than 10 minutes to complete. This time constraint is quite challenging in the security context, as many of the currently existing tools can't run in that short amount of time (#manoranjan, #mcgraw).

Todo: Automating security tools in Jenkins,...

#### References

- [manoranjan] - P. Manoranjan. Official (ISC)2 Guide to the CSSLP CBK, Second Edition ((ISC)2 Press) 2nd Edition, 2013
- [mcgraw] - G McGraw. Software Security: Building Security In, 2006

