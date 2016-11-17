## Tampering and Reverse Engineering

Mobile app security testing requires at least basic reverse engineering skills for several reasons.

**1. To enable black-box testing of mobile apps.** Modern apps often employ technical controls that will hinder your ability to perform dynamic analysis. SSL pinning and E2E encryption could prevent you from intercepting or manipulating traffic with a proxy. Root detection could prevent the app from running on a rooted device, preventing you from using advanced testing tools. In this cases, you must be able to deactivate these defenses.

**2. To enhance static analysis in black-box security testing.** In a black-box test, static analysis of the app bytecode or binary code is helpful for getting a better understanding of what the app is doing. It also enables you to identify certain flaws, such as credentials hardcoded inside the app.

**3. To assess resiliency against reverse engineering.**  Apps that implement software protections according to MASVS L3 or L4 should be resilient against reverse engineering. In this case, testing the reverse engineering defenses ("resiliency assessment") is part of the overall security test. In the resiliency assessment, the tester assumes the role of the reverse engineer and attempts to bypass the defenses. Advanced reverse engineering skills are required to perform this kind of test.

Testers should be proficient in general reverse engineering techniques as well as the particular environment: The target architecture, operating system, binary format, programming language, and so on. They should also keep up-to-date with the newest techniques and tools available to reverse engineers.

Reverse engineering is a creative process: The best protection mechanisms are based on original ideas, so there is no generic process that always works. That said, we'll describe commonly used methods and tools later on, and give examples for tackling the most common defenses.
