# GitHub Actions

![OWASP MSTG](images/release_header.png)

Our workflows for GitHub Actions are located in `.github/workflows`.

## ✅ Checks

Usually we don't have to change anything here apart from upgrading the version of the included actions (e.g. `actions/checkout@v2`).

- **Markdown Linter** (`.github/workflows/checkLinks.yml`): runs a markdown linter using our config `.github/workflows/config/.markdownlint.json` (more about [configuration](https://github.com/igorshubovych/markdownlint-cli#configuration)).
- **URLs Checker** (`.github/workflows/checkLint.yml`): runs a URL checker using our config `.github/workflows/config/mlc_config.json` (this workflow usually gives false positives that we have to exclude in the config).
- **CodeQL Security Scan** (`.github/workflows/codeql-analysis.yml`): to detect security issues in our Python code.

## 📘 Document Generation

- Document (`.github/workflows/docgenerator.yml`): uses `.github/workflows/doc-gen-reusable.yml` to generate the MASVS once per language as PDF, ePub and Docx using `tools/docker/pandoc_makedocs.sh`. To learn more see the page ["How to Export"](3_How_to_Export.md#export-the-documents).
  > GitHub Feature: ["Reusing Workflows"](https://docs.github.com/en/actions/learn-github-actions/reusing-workflows)
- Machine Readable (`.github/workflows/docgenerator.yml`, job: `export`): uses `tools/export.py` to export the MASVS as (yaml, json, etc.). To learn more see the page ["How to Export"](3_How_to_Export.md#export-machine-readable-formats).

## Release

Releases are triggered by the `release`job in `.github/workflows/docgenerator.yml`. To learn more see the page ["How to Release"](1_How_to_Release.md).

## Security

Adding a new action to a workflow requires careful consideration of security impact. Some actions have a “Verified creator” badge that can help you decide the level of trust you place in the action creator. However, the best approach is to audit the code behind the action, just like you would for open source libraries, to assess whether it’s reasonably secure and doesn’t do anything suspicious like sending secrets to third-party hosts. Thankfully, many actions are designed for a single purpose and are relatively easy to read.

- https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions
- Keeping your GitHub Actions and workflows secure:
  - [Part 1: Preventing pwn requests](https://securitylab.github.com/research/github-actions-preventing-pwn-requests/)
  - [Part 2: Untrusted input](https://securitylab.github.com/research/github-actions-untrusted-input/)
  - [Part 3: How to trust your building blocks](https://securitylab.github.com/research/github-actions-building-blocks/)

Find even more details in ["Security hardening for GitHub Actions"](https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions).

### Approval for Running Workflows

When an outside contributor submits a pull request to a public repository, a maintainer with write access may need to approve any workflow runs.

Our default in ([Settings / Actions / Fork pull request workflows from outside collaborators](https://github.com/OWASP/owasp-masvs/settings/actions)) is: all first-time contributors require approval to run workflows.

Learn more [here](https://docs.github.com/en/actions/managing-workflow-runs/approving-workflow-runs-from-public-forks)
