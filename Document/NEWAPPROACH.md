# New Approach

## Current Problems:

The MSTG has a few issues:

1. Test controls are scattered in various files with no obvious mapping to the MASVS controls (or categories)
1. Not every MASVS control is currently covered by a test case
1. Information is often repeated in different test cases
1. It contains snippets of both secure and vulnerable code without consistency
1. It contains a lot of information which quickly becomes outdated. The added value of these sections is limited as the original documentation is typically very good already.
1. Some parts resemble a 'secure development guide', while the MSTG is supposed to be a testing guide
1. It contains a lot of information that is very old (e.g. java code exec vulnerability in webview bridge)
1. Content is unstructured (from a technical point of view)

## Proposed solutions:

1. Create a single file per test case. The structure of each test case is described below. General information is moved to a single location which can be referenced from the test cases. (Solves 1, 2, 8) 
1. Each test case will be structured the same and will focus on the actual testing, not the background information. (Solves 3, 4, 6, 8)
1. Reference official documentation wherever possible. Additional info can be added as long as there is added value to it. (Solves 5)
1. Define a cut-off version (e.g. Android 6 and iOS 12). Reevaluate yearly depending on device numbers. (Solves 7)


## Test Case Structure
​
Each test case has a title including the MSTG-ID(s) and:
​
- Overview (mandatory)
- Static Analysis (optional, only if not applicable)
- Dynamic Analysis (optional, only if not applicable)
​
### Overview

The Overview contains:

* The relevant MASVS control
* An introduction on the MASVS control (but not the general topic)
* The risk associated with not implementing this control

### Static & Dynamic Analysis

The tests focus on using the various tools to validate the MASVS control.

* Tools are never introduced; tools are introduced in a dedicated tools section of the guide
* As few code snippets as possible (ideally, no code snippets)
* Interpretation of the tool's output is encouraged

## General sections

There will be general sections for each platform:

* A tools section, which alphabetically lists all the tools   
    * Each section should refer to the official documentation as much as possible
    * Each tool should list the supported platform versions
* A techniques section. This section contains various techniques that are needed in order to perform testing. Examples are 'Acquiring an IPA file', 'Obtaining a MitM', 'Extracting exposed components from AndroidManifest', ...
    * The techniques can link to different tools that are available, with example usages if the tools have specific features for it
* A general introduction to the platforms, tying together all the different externally available resources.