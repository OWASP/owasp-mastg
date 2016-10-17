# Author's guide

This document contains guidelines for new authors joining the OWASP MSTG. Please read them carefully.

## Picking a Role

The OWASP MSTG is an open standard, so in principle everyone is welcome to contribute or become a chapter owner. We don't check CVs and there is no formal process to go through. That said, keep in mind that with great power comes great reponsiblity: Once you have commited to a role, you'll be expected to deliver quality content.

### Lead author

The lead author takes high-level ownership of a whole chapter or test case category such as [Testing Sensitive Data Storage on Android](https://github.com/b-mueller/owasp-mstg/blob/master/Document/Testcases/0x00a_OMTG-DATAST_Android.md). A lead author should:

1. Contribute an significant amount of quality content to the chapter(s) owned;
2. Coordinate the work of authors and reviews working on subchapters;
3. Manage pull requests for this chapter and ensure the quality of contributions;
4. Moderate discussions about issues in the chapter(s) owned;
5. Ensure that milestones for chapter are reached on time.

Lead authors are expected to be highly responsive and actively engage in discussions on GitHub and [Slack](https://owasp.slack.com/messages/project-mobile_omtg/details/). This requires significant effort, so you should only take up this role if you're sure you can put in the time. 

#### Permissions

Lead authors are given write access to the repository so they can review and merge pull requests for their respective chapters.

### Contributor

Contributors write content such as single test cases or parts of test cases. For example, a contributor could submit a how-to for testing the custom URL schemes exported by an app. Contributors should:

1. Deliver quality content on the selected topic;
2. Actively engage with the chapter owners and reviewers via GitHub and [Slack](https://owasp.slack.com/messages/project-mobile_omtg/details/)

#### Permissions

Contributors are not provided with write access and should instead fork a working copy of the repo. The chapter owner is responsible for reviewing and merging the content.

### Reviewer

Reviewers are subject matter experts that help ensure the quality of the MSTG. A reviewer will usually pick several chapters and test case groups, and are called upon whenever new content has been added to the selected sections of the MSTG. The reviewer should:

1. Ensure technical accuracy of the content reviewed;
2. Check for grammar and spelling errors;
3. Provide feedback and actively engage with the chapter owners and reviewers via GitHub and [Slack](https://owasp.slack.com/messages/project-mobile_omtg/details/)

In our experience, opinions will differ in many cases. Whenever differences cannot easily be resolved, open an issue on GitHub and bring it up for discussion. Usually, the open discussion will result in a resolution - if not, the lead author of the chapter in question has the last word.

## How to Become an Author

To become a contributor or reviewer, contact the lead author responsible for the chapter you are interested in. You can find their name, GitHub handle and email address [here](https://github.com/b-mueller/owasp-mstg/blob/master/attribution.md). Please always check with the chapter owner first, or you might end up working on a chapter that's already being done by someone else. Asking on the Slack channel is another option.

## Attribution and Acknowledgement

Lead authors, contributors and reviewer will be added to the [acknowledgements section](https://github.com/b-mueller/owasp-mstg/blob/master/Document/0x01-Acknowledgements.md) of the MSTG after their work has been added.

### Using Content from OWASP MSTG Beta 2

Originally, the OWASP MSTG was developed on Google Docs. Lead authors starting on a chapter should check this document first and transfer any usable content into the new version of the guide. Whenever content from the [Google Doc](https://docs.google.com/document/d/132Ose0jdQwN6Z_Fp0VOJtVdGCufIwligwmf6oT0lmK8/edit#) is used, the original authors must be credited. Unfortunately, this process can sometimes be painful, but there's no way around it (missing attribution one of the main reason we moved to GitHub). To determine the original authors try the following:

1. Check the owner, authors and reviewers column in the [project plan](http://goo.gl/SsXAvC) (now obsolete);
2. Check the revision history of the [Google Doc](https://docs.google.com/document/d/132Ose0jdQwN6Z_Fp0VOJtVdGCufIwligwmf6oT0lmK8/edit#);
3. If you still can't figure it out, ask on the [Slack channel] or on the [mailing list];
4. If the original author(s) aren't aware of the new MSTG, invite them to join.
5. Add the content to the new MSTG.
6. Add the original author(s) to the acknowledgemens and make a note in the attribution document.

Note that content may also originate from the [original "beta" version](https://docs.google.com/document/d/1Z2nCRfe84D3t3IuEm9idX51lh51uzIerFaCV0Z74tbA/edit?ts=56f10e7f).

## Writing a test case

All test cases should follow the following basic guidelines.

### MASVS mapping

The list of test cases in the MSTG maps 1:1 to the requirements in the [OWASP MASVS](https://github.com/OWASP/owasp-masvs). For example, OWASP MASVS V2.9 maps to the test case OMTG-DATAST-009:

- OWASP MASVS V2.9 "Verify that sensitive data does not leak to backups."

-  OMTG-DATAST-009: "Test for Sensitive Data in Backups"

The MSTG must be kept compatible to the equivalent version of the MASVS. Changes in the list of requirements are always done in the MASVS first, after which the MSTG is updated to match the new requirements.

### Structure of a Test Case

Test cases are split into markdown files by test case category and operating system. For each category, there is a generic list of test cases as well as one file per mobile OS with OS-specific instructions. At the moment, only iOS and Android are discussed in the guide, so there are three files per category.

Use the [test case templates](https://github.com/b-mueller/owasp-mstg/tree/master/Templates) to add a new category.

### Style guide

The following rules are meant to ensure consistency of the MSTG:

1. Keep the content factual, brief and focused. Avoid duplicating other sections of the guide;
2. Refrain from advertising commercial tools or services;
3. When giving technical instructions, address the reader in the second person;

Refer to [existing test cases](https://github.com/b-mueller/owasp-mstg/blob/master/Document/Testcases/0x00a_OMTG-DATAST_Android.md#OMTG-DATAST-009) for examples.

