# Scripts and Releases

## Overview

This folder contains scripts and assets needed to generate our deliverables.

Files:

- `scripts/`: Directory containing the scripts used for the generation of the MAS deliverables such as the website and the checklists.
- `contributors.py`: Python script to retrieve current contributors and group them into our different categories according to their additions.

## GitHub Actions

Our workflows for GitHub Actions are located in `.github/workflows`.

Usually we don't have to change anything here apart from upgrading the version of the included actions (e.g. `actions/checkout@v2`).

- **Document** (`.github/workflows/docgenerator.yml`) generates:
    - the MAS Checklist using `src/scripts/yaml_to_excel.py`
- **Build Website** (`.github/workflows/build-website.yml`): builds the website and pushes the result to the `gh-pages` branch.
- **Markdown Linter** (`.github/workflows/markdown-linter.yml`): runs a markdown linter using our config `.markdownlint.json` (more about [configuration](https://github.com/igorshubovych/markdownlint-cli#configuration)).
- **URLs Checker** (`.github/workflows/url-checker.yml`, `.github/workflows/url-checker-pr.yml`): runs a URL checker using our config `.github/workflows/config/url-checker-config.json` (this workflow usually gives false positives that we have to exclude in the config).
- **Spell Checker** (`.github/workflows/spell-checker.yml`): runs a spell checker
- **CodeQL Security Scan** (`.github/workflows/codeql-analysis.yml`): to detect security issues in our Python code.
- **Labeler** (`.github/workflows/labeler.yml`): automatically labels PRs based on the files changed and the configuration in `.github/labeler.yml`.

## How to Release

See ["How to Release"](https://github.com/sushi2k/MSTG-MASVS-Internal/blob/main/docs/release/1_How_to_Release.md) (access restricted).
