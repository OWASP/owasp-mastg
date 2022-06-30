# Release Process

We use Github actions to build and verify the documents and to trigger releases. The output of a release is:

- The collection of [MSTG Release Assets](https://github.com/OWASP/owasp-mstg/releases) (incl. the OWASP Mobile Security Checklists and exported files such as YAML and CSV)
- The collection of [MASVS Release Assets](https://github.com/OWASP/owasp-masvs/releases) (incl. the MASVS in all languages and exported files such as YAML and CSV).
- The new MSTG version published on [GitBook](https://mobile-security.gitbook.io/mobile-security-testing-guide/)
- The new MASVS version published on [GitBook](https://mobile-security.gitbook.io/masvs)

## How to Release

The CHANGELOG is handled *automagically* by GitHub. Still, step 1 you'll review the latest changes so that the Release Notes are meaningful and comprehensive.

> The release is configured in `.github/release.yml` including categories and excluded labels used to exclude PRs.

1. Review the merged PRs since the last release, they should have:
    - Good titles (so you don't even have to open it to understand what has changed)
    - Appropriate tags. For example:
      - In the MSTG, add the `tests` tag if you have created or updated a test case.
      - In the MASVS, add the `change-masvs` if you changed a MASVS requirement.
      - Add the `ignore-for-release` label to exclude it from the Release Notes (useful for some minor changes that aren't interesting for users).
2. Checkout master and pull changes:

    ```bash
    git checkout master
    git pull
    ```

3. Push a new tag **using semantic versioning!!**:

    ```bash
    git tag -a v1.4.1 -m "Release v1.4.1" && git push origin v1.4.1
    ```

4. Wait until the Document Build Github Action in "actions/workflows/docgenerator.yml" finishes running (~5 min).
5. The **Release Draft** is ready, click on the edit icon:
    - review the generated log, include extra info if needed.
    - scroll to see all assets.
    - check "Create a discussion for this release" so that it's announced in Discussions.
    - click on **Publish Release**

## 📣 Announcing the Release

1. Update [OWASP Wiki](https://github.com/OWASP/www-project-mobile-security-testing-guide) if necessary.
2. Tweet about it via [@OWASP-MSTG](https://twitter.com/OWASP_MSTG)
3. Post on LinkedIn
4. Announce on OWASP Slack (#project-mobile_omtg, #owasp-community, #leaders).

## 📖 GitBook Release

Currently using @sushi2k's repositories which are synced automatically via https://github.com/apps/pull.

- <https://github.com/sushi2k/owasp-masvs>
- <https://github.com/sushi2k/owasp-mstg>

## 🗑 Deleting a Release

In case something went wrong and we need to remove the release:

1. **Delete the Release Draft** in <https://github.com/OWASP/owasp-masvs/releases> or <https://github.com/OWASP/owasp-mstg/releases>.
2. **Delete the tag** locally and remotely:

    ```bash
    git tag -d v1.4.1   # delete the tag locally
    git push --delete origin v1.4.1  # delete the tag remotely
    ```
