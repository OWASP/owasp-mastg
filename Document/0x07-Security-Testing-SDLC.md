# Appendix

## Security Testing in the Software Development Lifecycle

The history of software development is not that old after all, and it is easy to see that, rapidly, teams have stopped developing programs without any framework: we have all experienced the fact that, as the number of lines of code grows, a minimal set of rules are needed in order to keep work under control, meet deadlines, quality and budgets. 

In the past, the most widely adopted methodologies were from the "Waterfall" family: development was done from a starting point to a final one, going through several steps, each of them happening one after the other in a predefined sequence. In case something was wrong during a given phase and something had to be changed in a former phase, it was possible to go only one step backward. This was a serious drawback of Waterfall methodologies. Even if they have strong positive points (bring structure, clarify where to put effort, clear and easy to understand, ...), they also have negative ones (creation of silos, slow, specialized teams, ...). 

As time was passing and software development was maturing, also competition was getting stronger and stronger, and a need to react faster to market changes while creating software products with smaller budgets rose. The idea of having fewer structure with smaller teams collaborating together, breaking silos through the organization from marketing to production, became popular. The "Agile" concept was born (well known examples of Agile implementations are Scrum, XP and RAD), which was enabling more autonomous teams to work together in a faster manner.

Originally, security was not part of software development. It was seen as an afterthought, and was performed by Operation teams at the network level: those teams had to find ways to compensate for poor security in software programs! However, while this was possible when software programs were located inside a perimeter, the concept became obsolete as new ways to consume software emerged with Web and Mobile technologies. Nowadays, security has to be baked **inside** software as it is often very hard in this new paradigm to compensate for existing vulnerabilities.

The way to incorporate security during software development is to put in place a Secure SDLC (Software Development Life Cycle). A Secure SDLC does not depend on any methodology nor on any language, and it is possible to incorporate one in Waterfall or Agile: no excuse not to use one!
This chapter will focus on Agile and Secure SDLC, in particular in the DevOps world. The reader will find below details on state-of-the-art ways to develop and deliver secure software in a fast-paced and collaborative manner that promotes autonomy and automation.

### Agile and DevOps

#### DevOps

DevOps refers to practices that focus on a close collaboration between all stakeholders involved in delivering software. DevOps is the logical evolution of Agile in that it enables software to be released to users as rapidly as possible. Besides the collaboration aspect, to a large extent, this is facilitated through heavy automation of the build, test and release process of software and infrastructure changes. This automation is embodied in the deployment pipeline.

##### Todo: Add deployment pipeline overview and description specific for mobile apps.

The term DevOps might be mistaken for only expressing collaboration between development and operations teams, however, as Gene Kim, a DevOps thought leader, puts it: “At first blush, it seems as though the problems are just between dev and ops," he says, "but test is in there, and you have information security objectives, and the need to protect systems and data. These are top-level concerns of management, and they have become part of the DevOps picture."

In other words, when you hear "DevOps" today, you should probably be thinking DevOpsQATestInfoSec.” (Source: https://techbeacon.com/evolution-devops-new-thinking-gene-kim)

Security is just as important for the business success as the overall quality, performance and usability of an application. As development cycles are shortened and deployment frequencies increased it is elementary to ensure that quality and security is built in from the very beginning.

From the human aspect, this is achieved by creating cross functional teams that work together on achieving business outcomes. This section is going to focus on the interaction with and integration of security into the development life-cycle, from the inception of requirements, all the way until the value of the change is made available to users.

### Approach

Start by doing risk assessment
-> Define data classification (What is considered sensitive data in your org)
-> Set the according ASVS level
-> Integrate requirements into ALM
-> Threat model for design
-> Provide secure coding guidelines to the devs
-> Provide test cases for qa folks
-> Automate as many security tests as possible in the deployment pipeline
-> Perform exploratory security testing
-> Close feedback loop to dev team

### General Considerations

* Release time for apple store
* Why are black listed, and how to avoid it.
* Common gotchas: Ensure that the app is always fully removed and re-installed. Otherwise there might be issues that are hard to re-produce.
*

### SDLC Overview

#### General description of SDLC

Whatever the development methodology that is being used, a SDLC always follows the same process:
* at the beginning of a project or a development cycle, at the same time when functional requirements are gathered, **Security Requirements** are listed and clarified. As use cases are built, **Abuse Cases** are added. Also, **Security Risks** are analysed, as other risks of the project (financial, marketing, industrial, ...). Teams (including development teams) may be trained on security if needed (Secure Coding, ...);
* then, as architecture and design are ongoing, a foundational artefact must be performed: **Threat Modeling**. Based on it, **Security Architecture** is defined (both on the software and hardware sides). **Secure Coding rules** are established and the list of **Security tools** that will be used is created. Also, the strategy for **Security testing** is clarified;
* the next step is to develop software, including **Code Reviews** (usually with peers), **Static Analysis** with automated tools and **Unit Tests** dedicated to security;
* then comes the long-awaited moment to perform tests on released codes: **Penetration Testing** ("Pentests"), using both manual and automated techniques; 
* and finally, after software has been **Accredited** by all stakeholders, it can be transitioned to Operation teams and safely put in Production. 

The picture below shows all the phases with the different artefacts:
-- TODO : Add a picture of a SDLC diagram that clarifies the description above --

Based on the risks of the project, some artefacts may be simplified (or even skipped) while others may be added (formal intermediary approvals, documentation of certain points, ...). **Always keep in mind a SDLC is meant to bring risk reduction to software development and is a framework that helps put in place controls that will reduce those risks to an acceptable level. ** While this is a generic description of SDLC, always tailor this framework to the needs of your projects.

#### Diving into phases and artefacts

Now, let's have a closer look at the five phases listed above and let's clarify their main purposes, what is done while they take place and who performs them:
* **Initiation** phase: this is the first phase of a project, when requirements are gathered from the field and defined for the project. They should include both functional (e.g. what functions will be created for the end user) and security (e.g. what security features will need to be implemented to allow end users to trust the software product) requirements. In this phase, all activities that need to happen before technical work starts and all others that can be anticipated will take place. This is also the moment when Proof of Concepts may be done and when the project viability is confirmed. Typically, teams close to business functions such as Marketing (marketing people, or Product Owners, ...), Management and Finance are involved.
* **Architecture and Design** phase: after the project has been confirmed, the technical team will start working on early technical activities that will enable coding teams to be productive. In this matter, risks are analysed and relevant countermeasures identified and clarified, and architecture / coding and testing strategies / tools and environnements are created and put in place. This phase is pivotal as its main goal is to go from a non-technical definition of needs to the point where technical teams are ready to give birth to code that will make up the software product. Typically, Architects, Designers, QA teams and Testers are involved.
* **Coding** phase: this is the moment when code is produced and efforts become visible. This may be seen as the most important phase; however, one must keep in mind that all activities happening before and after the current phase are meant to support code creation and make sure it reaches proper standards for quality and security while meeting deadlines and budgets. In this phase, development teams work in the defined environnement to implement requirements following previously defined guidelines. The main people who are involved are developers.
* **Testing** phase: this is the phase when produced software is tested. As testing can take many forms (see detailed section on Security Testing in the SDLC below), testing activities may be performed during coding (the obvious goal being to discover issues as soon as possible). Depending on organizations, the project risk profile and techniques used, testing teams may be independent from coding teams. The main people involved during this phase are Testers.
* **Release** phase: at this point of time, code has been created and tested. Its security level has been assessed; often, metrics are produced to support evidence that code meets the expected level of security. However, it has now to be transitioned to the Customer, e.g. it has to be accepted by stakeholders (Management, Marketing, ...) as able to create value on the market and be of economical interest to Customers; next to that, it will be made available to the market. It is not enough to produce secure software, but it now has to be safely transitioned to Production environnements, which in turn must be secured (both in the short term and in the long term); documentation for Operation teams may be created. In this phase, stakeholders (Management, Marketing, ...) are first involved, as well as technical teams (Testing, Operations, Quality, ...).

Even if the previous description seems to be "Waterfall-like", it also applies to Agile methodologies: the same logic is used, but in a more iterative manner. Some activities may be done only once (for instance project initiation), however smaller parts of similar activities will happen regularly all along the project (like bringing new requirements into light and clarifying them into Stories). In the same manner, testing will not happen only once at the end of a project, but, on each iteration, tests will focus on the amount of code that was produced in the iteration.

### Security Testing in the SDLC

#### Overview

A well-known statement in software development (and many other fields as well) is that the sooner tests take place, the easier and more cost-effective it is to fix a defect. The same applies to defects related to cyber security: identifying (and fixing) vulnerabilities early in the development lifecycle gives better results when it comes to produce secure software. In some ways, Quality Testing and Security Testing may share common aspects as both are meant at the end of the day to raise Customer satisfaction.

Testing can be performed in many forms during the lifecycle: using automated tools for Static Analysis, writing Unit Tests as code is being created, running pentests (either manually or with the help of scanning tools) after software has been developed, ... However, an emphasis should always be put on planning and preparing these efforts early in the Secure SDLC: a Test Plan should be initiated and developed at the beginning of the project, listing and clarifying the kind of tests that will be executed, their scope, how and when they will take place and with what budget. Also, Abuse cases should be written early in the project (ideally at the same time when Use Cases are created) to provide guidance to test teams all along development. Finally, an artefact that should always be considered is Threat Modeling, which allow team to focus on the right components in the architecture with the proper tests and proper coverage that will check the efficiency of the controls put in place.

The following diagram provides an overview of the way to perform test in the SDLC:

-- TODO : add diagram to summarize the above paragraph and clarify the way test should be performed (planned, executed and reviewed)

#### Detailed Description

As stated before, several kinds of tests can be made along the SDLC. According to the risk profile of the targeted software, several kind of tests can be made :
* **Static Analysis**: by nature, static analysis is about analysing source code without running it. The goal of this artefact is twofold: make sure the Secure Coding rules the team has agreed on are correctly implemented when writing code, and finding vulnerabilities. Often, specialized software tools are used to automate this task, as hundreds and thousands of lines of code may need to be analysed. However, the drawback is that tools can only find what they have been told to look for and, today, are not as successful as human beings. This is the reason why sometimes Static Analysis is performed by humans (in addition to tools or not): it may take more time to humans, but they have a more creative way to detect vulnerabilities. Examples of tools for Static Analysis are given in another section.
* **Unit Tests**: unit tests make up the family of tests that are the closest to source code (e.g. they are focused on a single unit) as they are performed along with code. According to the methodology in use, they can be created either before code is developed or right after. Whatever the case, the end goal is to verify that procuced code is behaving as expected, but also that proper controls are put in place to prevent abuse cases (input filtering / validation, whitelisting, ...) and cannot be circumvented. Unit Tests are used to detect issues early in the development lifecycle to be able to fix them as soon and easily as possible. They are different from other forms of tests, like Integration / Verification / Validation tests, and may not be used to detect the same kind of issue. Often, Unit Tests are aided with tools; a few of them are listed in another section.
* **Penetration Testing**: this is the "king" of security tests, the one that is the most famous and often performed. However, one must keep in mind that they happen late in the development lifecycle and that they cannot find every kind of flaw. They are too often constrained by available resources (time, money, expertise, ...), and as such should be complemented by other kind of tests. The current guide is about pentesting, and the reader will find a lot of useful information to conduct added-value tests and find even more vulnerabilities. Pentesting techniques include vulnerability scanning and fuzzing; however, pentests are much larger than these two examples. Useful tools are listed in another section.

A clear difference shall be made between quality testing and security testing: while quality testing is about making sure an explicitely planned feature has been implemented in the proper way, security testing is about making sure
- existing features cannot be used in a malicious way 
- no new feature has unvoluntarily been introduced that could endanger the system or its users.

As a consequence, performing one type of tests is not enough to pretend having covered both types and that the produced software is both usable and secure. The same care should be given to both types of tests as they are of the same importance and that final users now put a strong emphasis both on quality (e.g. the fact features that are brought to them perform the way they expect them to) and security (e.g. that they can trust the software vendor that their money will not be stolen or their private life will remain private). 

#### Defining a Test Strategy

The purpose of a test strategy is to define which tests will be performed all along the SDLC and how often. Its goal is twofold: make sure security objectives are met by the final software product, which are generally expressed by customers / legal / marketing / Corporate teams, while bringing cost-effectiveness. The test strategy is generally created at the beginning of a project, after risks have been clarified (Initiation phase) but before code production (Coding phase) starts. It generally takes place during the Architecture and Design phase. It takes inputs from activities such as Risk Management, Threat Modeling, Security Engineering, ...

-- TODO : add diagram (in the form of a workflow) showing inputs of a Test Strategy, and outputs (test cases, ...) --

A Test Strategy does not always need to be formally written: it may be described through Stories (in Agile projects), quickly written in the form of checklists, Test Cases could be written in a given tool, ... ; however, it definitely needs to be shared, as it may be defined by the Architecture team, but will have to be implemented by other teams such as Development, Testing, Quality, ... Moreover, it needs to be agreed upon by all technical teams as it should not place unacceptable burdens on any of them. 

Ideally, a Test Strategy addresses topics such as:
- objectives to be met and description of risks to be put under control.
- how these objectives will be met and risks reduced to an acceptable level: which tests will be mandatory, who will perform them, how, when, at which frequency.
- acceptance criteria of the current project.

In order to follow its effectiveness and progress, metrics should be defined, updated all along the project and periodically communicated. An entire book could be written on the relevant metrics to choose; the best that can be said is that they depend on risk profiles, projects and organizations. However, some examples can be given : metrics include 
- the number of stories related to security controls that are implemented,
- code coverage for unit tests on security controls and sensitive features,
- the number of security bugs found by static analysis tools upon each build,
- the trend of the backlog for security bugs (may be sorted by criticality).
These are only suggestions, and other metrics may be even more relevant in your case. Metrics are really powerful tools to put under control a project, provided they give a clear view and in a timely manner to project managers on what is happening and what needs to be improved to reach targets.


--

### Testing methods
#### White box
#### Grey box
#### Black box
### Team management
-- TODO :

- explain the importance of Separation of Duties (developers VS testers, ...)
- internal VS sub-contracted pentests

### References

- [1] Meyer's Recipe for Tomato Soup - http://www.finecooking.com/recipes/meyers-classic-tomato-soup.aspx
- [2] Another Informational Article - http://www.securityfans.com/informational_article.html
