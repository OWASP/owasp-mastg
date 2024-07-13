# MASVS-RESILIENCE: Resilience Against Reverse Engineering and Tampering

Defense-in-depth measures such as code obfuscation, anti-debugging, anti-tampering, etc. are important to increase app resilience against reverse engineering and specific client-side attacks. They add multiple layers of security controls to the app, making it more difficult for attackers to successfully reverse engineer and extract valuable intellectual property or sensitive data from it, which could result in:

- The theft or compromise of valuable business assets such as proprietary algorithms, trade secrets, or customer data
- Significant financial losses due to loss of revenue or legal action
- Legal and reputational damage due to breach of contracts or regulations
- Damage to brand reputation due to negative publicity or customer dissatisfaction

The controls in this category aim to ensure that the app is running on a trusted platform, prevent tampering at runtime and ensure the integrity of the app's intended functionality. Additionally, the controls impede comprehension by making it difficult to figure out how the app works using static analysis and prevent dynamic analysis and instrumentation that could allow an attacker to modify the code at runtime.

Note, however, that **the absence of any of these measures does not necessarily cause vulnerabilities** - instead, they provide additional threat-specific protection. **All apps must also fulfill the rest of the OWASP MASVS** security controls according to their specific threat models.
