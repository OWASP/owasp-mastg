# Appendix

## Security Testing in the Software Development Lifecycle

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

-- TODO :

- SDLC complements classical software development lifecycles and can be integrated in all of them
- SDLC diagram and description
- Quick description of all phases

--

### Secure Software Testing
-- TODO :

- Explain how it relates to and differs from Quality testing
- Explain the different types of tests (unit, Verification, Validation, ....)

--
### Technical Management
#### Test Strategy
-- TODO : Describe what a Security Test Strategy is, how it relates to other artefacts (Threat Model, Requirements, ...), how it is declined into Test Plans and Test Cases --
#### Test Case
-- TODO : Describe a typical test case for Security --
#### Reporting and Issue tracking
-- TODO : Explain reporting and Issue tracking (principles and popular tools) --
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
