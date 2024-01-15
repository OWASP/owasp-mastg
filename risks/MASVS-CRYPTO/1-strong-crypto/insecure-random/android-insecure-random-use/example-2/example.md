## Example 2

### Sample

{{ random-password.java }}

### Steps

Let's run our sempgrep rule against the sample code.

{{ ../rules/mstg-crypto-6.yaml }}

{{ run.sh }}

### Observation

The rule has identified one instance in the code file where an insecure random number generator is used. The specified line number can be located in the original code for further investigation and remediation.

{{ output.txt }}

### Evaluation

The test case fails because line 15 is part of the password generation function which is a security-critical operation.
