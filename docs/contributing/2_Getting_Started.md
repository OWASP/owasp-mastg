# Getting Started

First of all **Create a GitHub account** (a free one is enough) by following [these steps](https://docs.github.com/en/get-started/signing-up-for-github/signing-up-for-a-new-github-account).

Our workflow is like this:

1. **Open a [Discussion](https://docs.github.com/en/discussions)** (for ideas and proposals)
If your proposal qualifies for the MSTG/MASVS we'll convert it into an "Issue" (the discussion might take a while).

- MASVS Example: "Add a MASVS-CRYPTO requirement on Key rotation"
- MSTG Example: "Add a Test case for key rotation"

2. **Open an Issue** (for concrete actionable things that have to / could be done)
For instance, there's a typo, or it's clear that a certain Test case doesn't have e.g. "Dynamic Analysis" and it should be added.
3. **Open a PR** (to add actual content)
This could be the fix for the mentioned typo, a whole new section or some other content. Usually a PR has a "closes" sentence in its description. For example "Closes #543" so that we (and GitHub) know which Issue(s) is being addressed on that PR.

Normally, contributors should follow the whole flow. But sometimes it's clear what's needed so we directly go to 2 (open an issue) or even to 3 (open a PR). **We recommend starting with a discussion or directly [contacting us](https://github.com/OWASP/owasp-mstg#connect-with-us)** to save you the hurdle of writing and submitting new content that does not qualify so we have to reject it after the work is done.

If you just have an **specific question** you can post it to (you need a [GitHub Account](https://docs.github.com/en/get-started/signing-up-for-github/signing-up-for-a-new-github-account)):

- https://github.com/OWASP/owasp-masvs/discussions/categories/q-a
- https://github.com/OWASP/owasp-mstg/discussions/categories/q-a

"GitHub Discussions" are re-posted to [our Slack channel](https://owasp.slack.com/messages/project-mobile_omtg/details/).

Once you get your answer please [mark it as answered](https://docs.github.com/en/discussions/collaborating-with-your-community-using-discussions/participating-in-a-discussion#marking-a-comment-as-an-answer). When you mark a question as an answer, GitHub will highlight the comment and replies to the comment to help visitors quickly find the answer.

![Answer](https://docs.github.com/assets/cb-62285/images/help/discussions/comment-marked-as-answer.png)

## Contribute Online

GitHub makes this extremely easy.

For small changes in one file:

1. Go to the file you'd like to modify and [click on "Edit"](https://docs.github.com/en/repositories/working-with-files/managing-files/editing-files#editing-files-in-another-users-repository).
2. Do your changes and commit them. GitHub will guide you and suggest to open a Pull Request.

For more complex changes or across files:

1. Press `.` while browsing the repo or pull request.
2. You'll be welcomed with a ["github.dev Web-based Editor"](https://docs.github.com/en/codespaces/the-githubdev-web-based-editor) where you can work using an online Visual Studio.
3. Do your [changes, commit and push](https://docs.github.com/en/codespaces/the-githubdev-web-based-editor#using-source-control) them as you'd do locally.

![github.dev](https://user-images.githubusercontent.com/856858/130119109-4769f2d7-9027-4bc4-a38c-10f297499e8f.gif)

Learn more about the github.dev Web-based Editor in ["GitHub Docs"](https://docs.github.com/en/codespaces/the-githubdev-web-based-editor).

## Contribute Offline

For this you need an IDE or text editor and git on your machine. We recommend using the free [Visual Studio Code editor](https://code.visualstudio.com "Visual Studio Code") with the [markdownlint extension](https://marketplace.visualstudio.com/items?itemName=DavidAnson.vscode-markdownlint).

1. [Fork the repo](https://docs.github.com/en/get-started/quickstart/fork-a-repo#forking-a-repository). Forking the repo allows you to make your changes without affecting the original project until you're ready to merge them.
2. [Clone your fork repo](https://docs.github.com/en/repositories/creating-and-managing-repositories/cloning-a-repository#about-cloning-a-repository) and [add the remote upstream repo](https://docs.github.com/en/get-started/using-git/pushing-commits-to-a-remote-repository#remotes-and-forks), e.g. for owasp-masvs:
    ```bash
    $ git clone https://github.com/<your_github_user>/owasp-masvs.git
    $ git remote add upstream git@github.com:OWASP/owasp-masvs.git
    ```
3. Create a branch.
    ```bash
    $ git checkout -b fix-issue-1456
    ```
4. Make your changes.
5. Commit and push your changes. This can be done by executing the command `git add MYFILE` for every file you have modified, followed by `git commit -m 'Your Commit Message'` to commit the modifications and `git push` to push your modifications to GitHub.
6. [Open a PR](#how-to-open-a-pr).
