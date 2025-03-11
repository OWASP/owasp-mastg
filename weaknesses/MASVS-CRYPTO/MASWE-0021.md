---
title: Weak, Risky or Broken Hashing
id: MASWE-0021
alias: weak-hashing
platform: [android, ios]
profiles: [L1, L2]
mappings:
  masvs-v1: [MSTG-CRYPTO-4]
  masvs-v2: [MASVS-CRYPTO-1]
  cwe: [328]

refs:
- https://developer.android.com/privacy-and-security/cryptography#deprecated-functionality
- https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-131Ar2.pdf
- https://cwe.mitre.org/data/definitions/328.html
- https://en.wikipedia.org/wiki/Collision_attack
- https://csrc.nist.gov/pubs/ir/8547/ipd
draft:
  description: Utilizing weak hashing algorithms such as MD5 and SHA1 in a security
    sensitive context may compromise data integrity and authenticity.
  topics:
  - Weak hashing algorithms (e.g. MD5, SHA1, etc.)
status: draft
---

Choosing a weak hash algorithm, that is insufficiently collision resistant, may compromise the integrity and authenticity of data at rest and in transit by opening the application up for collision attacks.

when performing key derivation together with predictable input or in password hashing, the digest (or hash) of an improper implemented- or used hash function may allow and adversary to reasonably determine the original input (preimage attack), find another input that can produce the same hash (2nd preimage attack), or find multiple inputs that evaluate to the same hash (birthday attack/collision attack), given the actor can arbitrarily choose the inputs to be hashed and can do so a reasonable amount of times

What is regarded as "reasonable" varies by context and threat model, but in general, "reasonable" could cover any attack that is more efficient than brute force (i.e., on average, attempting half of all possible combinations). Note that some attacks might be more efficient than brute force but are still not regarded as achievable in the real world.

Any algorithm that does not meet the above conditions will generally be considered weak for general use in hashing. When a collision attack is discovered and is found to be faster than a birthday attack, a hash function is often denounced as "broken". This is the case for MD5 and SHA-1.

Another common issue is using HKDF for key derivation with any type of integrity based hashing algorithm like MD5, SHA-1, SHA-2 or even SHA-3 on low-entropy input like user supplied passwords and pins. HKDF aren't design for low-entropy inputs. Doing so will result in producing "weak" hashes that easily can be broken.

## Impact

- **Loss of Integrity and authenticity**: A weak, risky or broken hashing algorithm, may allow an attacker to compromise the integrity and authenticity of data at rest and in transit.
- **Loss of Confidentiality**: A  weak, risky or broken hashing algorithm may expose the preimage (input) and in so doing break the confidentiality.
- **Risk of Brute-Force Attacks**: A  weak, risky or broken hashing is susceptible to brute-force attacks.

## Modes of Introduction

- **using a weak, risky or broken hashing algorithm**: E.g: MD5 and SHA-1 has been identified to be vulnerable for collision attacks that are faster than a birthday attack. Meaning that they are denounced as "broken".
- **Using a insufficiently collision resistant hash**: Choosing a a hashing algorithm of insufficient length may result in loss of integrity or confidentiality.
- **Using non-resource intensive algorithms on low-entropy input**: Using a integrity based hashing algorithm to hash low-entry input like pin numbers would make brute-force or dictionary attacks trivial.


## Mitigations

- **Choose collision resistant algorithm**: Choose an algorithm that is sufficiently collision resistant like the integrity algorithms SHA-256, SHA-384, SHA-512, BLAKE3 and the SHA-3 family
- **Choose an algorithm with sufficient bit-lengths**: As our computers gets stronger, the hashes gets weaker, therefor, make sure that you can adjust the bit-length length of the algorithm of your choosing. When hashes are stored at rest, make sure to follow the software industry's long term recommendations (e.g: ["NIST: Transition to Post-Quantum Cryptography Standards](https://csrc.nist.gov/pubs/ir/8547/ipd)").
- **Choose an algorithm fit for it's purpose**: When you want to ensure the data's integrity choose a integrity based algorithm. When you want to hash low-entropy input choose a password hash algorithm. Don't try to be clever. Follow recommendations and guidelines.