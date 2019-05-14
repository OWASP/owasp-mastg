# Contributing

## How to contribute

Contributing to the MSTG can be done in many different ways:

### Creating issues

* Create [Issues] for missing content or errors. Explain what you think is missing and give a suggestion as to where it could be added. 
* Create a [Pull Request (PR)](https://github.com/OWASP/owasp-mstg/pulls "Create a pull request"). This is a direct contribution to the guide and your PR may be merged after review. Be sure to follow our [style guide](https://github.com/OWASP/owasp-mstg/blob/master/style_guide.md "MSTG Style Guide") when writing content. You should ideally create an issue for any PR you would like to submit, as we can first review the merit of the PR and avoid any unnecessary work. This is of course not needed for small modifications such as correcting typos.
* Review pull requests. If you are a fluent speaker in any of the different languages that the MSTG is available in, feel free to give feedback on any of the submitted PRs.
* Proofread and fix errors. If you are studying the MSTG, write down any error, no matter how small, and submit them in an Issue or fix them yourself through a PR.

//todo; check https://github.com/OWASP/CheatSheetSeries/blob/master/CONTRIBUTING.md : spelling, full setup or issues

//add reference to the style-guide: Quality of written content is just as important as the content

//add We review before merge (e.g. line out process and max response time at )

// add that the code snippets must be well tested and maybe give some hints on the target apps people is allowed to use, e.g. open source apps, give preference to the hacking playground app or other OWASP apps like iGoat

//Use PR template: make sure that you fullfill all requirements (and check them)

## How to set up my contributor environment

1. Create a GitHub account. Multiple different GitHub subscription plans are available, but you only need a free one. Follow [these steps](https://help.github.com/en/articles/signing-up-for-a-new-github-account "Signing up for a new GitHub account") to set up your account. 
2. Fork the repository. Creating a fork means creating a copy of the repository on your own account, which you can modify without any impact on this repository. GitHub has an [article that describes all the needed steps](https://help.github.com/en/articles/fork-a-repo "Fork a repo").
3. Clone your own repository to your machine so that you can make modifications. If you followed the GitHub tutorial from step 2, you have already done this.
4. Choose what to work on, based on any of the outstanding [issues](https://github.com/OWASP/owasp-mstg/issues "MSTG Issues").
5. Create a branch so that you can cleanly work on the chosen issue: `git checkout -b FixingIssue66`
6. Open your favorite editor and start making modifications. We recommend using the free [Visual Studio Code editor](https://code.visualstudio.com "Visual Studio Code") as it can make use of the code linting that is part of the repository through the [MarkdownLint plugin](https://github.com/DavidAnson/vscode-markdownlint#install "MarkdownLint plugin"). The code linter can help you when you make mistakes against our [style guide](https://github.com/OWASP/owasp-mstg/blob/master/style_guide.md "MSTG Style Guide"), but be sure to read the style guide yourself, as the code linter will only detect a part of it.
7. After your modifications are done, push them to your forked repository. This can be done by executing the command `git add MYFILE` for every file you have modified, followed by `git commit -m 'Your Commit Message'` to commit the modifications and `git push` to push your modifications to GitHub. If this is the first time that you push the branch to GitHub, you will receive an error about a missing remote branch. Simply copy & paste the suggested fix to create the remote branch (Example: `git push --set-upstream origin FixingIssue66`)
8. Create a Pull Request (PR) by going going to the [Create Pull Request page](https://github.com/OWASP/owasp-mstg/pull/new/master) and selecting your newly created branch. The target branch should typically be the Master branch. When submitting a PR, be sure to follow the checklist that is provided in the PR template. The checklist itself will be filled out by the reviewer.
9. Your PR will be reviewed and comments may be given. In order to process a comment, simply make modifications to the same branch as before and push them to your repository. GitHub will automatically detect these changes and add them to your existing PR.

If at any time you want to work on a different issue, you can simply switch to a different branch, as explained in step 5. Don't try to work on too many issues at once though, as it will be a lot more difficult to merge branches the longer they are open.

## What not to do

Although we greatly appreciate any and all contributions to the project, there are a few things that you should take into consideration:

* The MSTG should not be used as a platform for advertisement of commercial tools. Write-ups should be written with free and open-source tools in mind and commercial tools are typically not accepted, unless as a reference in the security tools section.
* Unnecessary self-promotion of tools or blog posts is frowned upon. If you have a relation with on of the URLs or tools you are referencing, please state so in the PR so that we can verify that the reference is in line with the rest of the guide.


//TODO: add markdown stylesheet to root so that studio is ok.
//TODO: add markdown checker as part of the build process
  - sudo apt-get install python3.5
  - npm install -g markdownlint-cli
  - npm install -g markdown-link-check
  - npm install -g gitbook-cli
//todo: add shellscripts as shown at https://github.com/OWASP/CheatSheetSeries/tree/master/scripts