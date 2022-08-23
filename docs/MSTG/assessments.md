From: https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-160v1.pdf

F.1 SECURITY ARCHITECTURE AND DESIGN
F.1.1 Clear Abstractions
F.1.2 Least Common Mechanism
F.1.3 Modularity and Layering
F.1.4 Partially Ordered Dependencies
F.1.5 Efficiently Mediated Access
F.1.6 Minimized Sharing
F.1.7 Reduced Complexity
F.1.8 Secure Evolvability
F.1.9 Trusted Components
F.1.10 Hierarchical Trust
F.1.11 Inverse Modification Threshold
F.1.12 Hierarchical Protection
F.1.13 Minimized Security Elements
F.1.14 Least Privilege
...
F.1.18 Trusted Communication Channels
...

F.2.5 Secure Defaults
...
F.4.2 Defense in Depth


## VE-2.2 Perform security verification procedures.

Discussion: Security verification, in accordance with the verification strategy, occurs at the
appropriate times in the system life cycle for the artifact identified by the verification procedure.

Correctness:
Security correctness procedures address capability, behavior, outcomes, properties, characteristics,
performance, effectiveness, strength of mechanism/function, precision, accuracy, in consideration
of identified constraints.
Vulnerability:
Security vulnerability procedures address flaws, deficiencies, and weaknesses that can be
intentionally or unintentionally leveraged, exploited, triggered, or that may combine in some
manner to produce an adverse consequence.
Penetration:
Security penetration procedures address strategically and/or tactically planned and controlled
methods with intent to defeat, overwhelm, overcome, or bypass the protection capability,
technologies, materials, or methods. Penetration procedures may simulate the actions of a given
class of adversary within the context of specific rules of engagement, using the knowledge,
methods, techniques, and tools the adversary is expected to employ to achieve an objective.
Abuse and misuse:
Security abuse and misuse procedures address the manner in which the system can be utilized to
produce unspecified behavior and outcomes. These procedures may target the security guidance,
policies, procedures, and any other available information directed at users, operators, maintainers,
administrators, and trainers. Abuse and misuse verification is able to identify overly complex,
erroneous, or ambiguous information that leads users, administrators, operators, or maintainers to
inadvertently place the system into a nonsecure state.

## G.6 SECURITY RELEVANCE

In the broadest sense, security relevance simply means that there is some security-driven or
security-informed aspect to a concern, issue, need, or outcome.

Security relevance is characterized and analyzed by using the following designations:69
• Security-enforcing functions: Security-enforcing functions are directly responsible for
delivering security protection capability, to include doing so in accordance with making or
enforcing security policy decisions. An example of a security-enforcing function is one that
makes the decision to grant or deny access to a resource.
• Security-supporting functions: Security-supporting functions contribute to the ability of
security-enforcing functions to deliver their specified capability. These functions provide
data, services, or perform operations upon which security-enforcing functions depend.
Generally, the dependence is at a functional level. Memory management is an example of a
security-supporting function.
• Security non-interfering functions: Security non-interfering functions are neither security-
enforcing or security-supporting but have the potential to adversely affect (i.e., interfere with
or corrupt) the correct operation of security-enforcing and security-supporting functions.
Security non-interfering should be interpreted as a design assurance objective, meaning that,
by design, these functions have no ability to interfere with or alter the behavior of security-
enforcing and security-supporting functions. The non-interfering objective is achieved
through security-driven constraints on the requirements, architecture, design, and use of these
functions.

> example: MASVS-CRYPTO, using MD5 for generating non-sensitive IDs (Security non-interfering function).


## G.8.2 Assurance
Assurance, in a general sense, is the measure of confidence associated with a set of claims. From
a security perspective, assurance is the measure of confidence that the security functions for the
system combine, in the context of the entire system, to provide freedom from the conditions that
cause asset loss and the associated consequences. 

The level of assurance obtained depends upon three interacting dimensions of scope, depth, and
rigor.81
• Scope: Assurance increases (and becomes more complete) as a greater percentage of the
system is considered in the analysis of system;
• Depth: Assurance increases as the analysis of the system reaches a finer level of introspection
into the design and implementation of the system and into the finer aspects of supporting and
enabling processes; and
• Rigor: Assurance increases as the methods, processes, and tools employed are more formal,
structured, and consistently repeatable and provide increased fidelity and rigor in execution
and results.


## G.8.3 Relationship to Verification and Validation
Verification and validation activities generate evidence to substantiate claims made about the
security capabilities, properties, vulnerabilities, and the effectiveness of security functions in
satisfying protection needs. The evidence used to substantiate claims can be objective or
subjective. For example, objective evidence could be pass-fail test results, whereas subjective
evidence is analyzed, interpreted, and perhaps combined with other evidence to produce a result.

...

The credibility and relevance of evidence should be confirmed prior to its use.
Some evidence can support arguments for strength of function, negative requirements (i.e., what
will not happen), and qualitative properties. **Subjective evidence is analyzed in the intended
context and correlated to the claims it supports via rationale.**
