## Example 2

### Sample

The following code generates a random password using `java.util.Random`:

{{ random-password.java }}

### Steps

{{ run.sh }}

### Observation

{{ output.txt }}

### Evaluation

The test case fails as you can find random numbers generated using those APIs that are used in security-relevant contexts, in this case to generate the password in line 15.
