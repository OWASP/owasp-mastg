import logging
import yaml
import mkdocs.plugins
import glob
from collections import defaultdict
import github_api
from html import escape
log = logging.getLogger('mkdocs')

def get_v1_tests_data():

    masvs_v1_tests_metadata = {}
    # Each test has an ID which is the filename
    for file in glob.glob("./tests/**/*.md", recursive=True):
        if "index.md" not in file:
            try:
                with open(file, 'r') as f:
                    content = f.read()
                    frontmatter = next(yaml.load_all(content, Loader=yaml.FullLoader))
                    # masvs category is frontmatter['masvs_v2_id'][0] without the final number. Example: MASVS-STORAGE-2 -> MASVS-STORAGE
                    masvs_category = frontmatter['masvs_v2_id'][0][:-2]
                    platform = frontmatter['platform']
                    # get id from filename without extension
                    id = file.split('/')[-1].split('.')[0]
                    link = f"https://mas.owasp.org/MASTG/tests/{platform}/{masvs_category}/{id}/"
                    frontmatter['link'] = link

                    masvs_v1_tests_metadata[id] = frontmatter
            except:
                log.warning("No frontmatter in " + file)

    # Populate the defaultdict with MASVS v1 IDs and corresponding MASTG-TEST IDs
    masvs_v1_mapping = defaultdict(list)
    for test_id, test_info in masvs_v1_tests_metadata.items():
        for masvs_id in test_info["masvs_v1_id"]:
            masvs_v1_mapping[masvs_id].append(f"[{test_id}]({test_info['link']})")

    return masvs_v1_tests_metadata, masvs_v1_mapping


beta_banner = """
??? example "Content in BETA"
    This content is in **beta** and still under active development, so it is subject to change any time (e.g. structure, IDs, content, URLs, etc.).

    [:fontawesome-regular-paper-plane: Send Feedback](https://github.com/OWASP/owasp-mastg/discussions/categories/maswe-mastg-v2-beta-feedback)
"""

def get_mastg_v1_coverage(meta, config):
    mappings = meta.get('mappings', '')

    if mappings:
        mastg_v1_tests_metadata, mastg_v1_mapping = config["v1_tests_data"]

        masvs_v1_id = mappings.get('masvs-v1', '')
        if len(masvs_v1_id) > 1:
            raise ValueError(f"More than one MASVS v1 ID found: {masvs_v1_id}")
        masvs_v1_id = masvs_v1_id[0] if masvs_v1_id else ""
        mastg_v1_tests_map = mastg_v1_mapping.get(masvs_v1_id, [])

        mastg_v1_tests_map_list = [f"{test.split(']')[0].split('[')[1]}" for test in mastg_v1_tests_map]
        mappings['mastg-v1'] = mastg_v1_tests_map_list

        mastg_v1_tests = "\n".join([f"    - [{test} - {mastg_v1_tests_metadata[test]['title']} ({mastg_v1_tests_metadata[test]['platform']})]({mastg_v1_tests_metadata[test]['link']})" for test in mastg_v1_tests_map_list])
        if mastg_v1_tests == "":
            mastg_v1_tests = "    No MASTG v1 tests are related to this weakness."
    return mastg_v1_tests

def get_maswe_placeholder_banner(meta, config):

    id = meta.get('id')

    refs = meta.get('refs', None)
    refs_section = ""
    if refs:
        refs_section = "    ## References\n\n"
        refs_section += "\n".join([f"    - <{ref}>" for ref in refs])

    placeholder_info = meta.get('draft', None)

    description = placeholder_info.get('description', None)

    if placeholder_info.get('note', None):
        description += "\n\n" + "    > Note: " + placeholder_info.get('note', None) + "\n"

    topics = placeholder_info.get('topics', None)
    topics_section = ""
    if topics:
        topics_section = "    ## Relevant Topics\n\n"
        topics_section += "\n".join([f"    - {topic}" for topic in topics])

    mastg_v1_tests = get_mastg_v1_coverage(meta, config)

    banner = f"""
!!! warning "Placeholder Weakness"

    This weakness hasn't been created yet and it's a **placeholder**. But you can check its status or start working on it yourself.
    If the issue has not yet been assigned, you can request to be assigned to it and submit a PR with the new content for that weakness by following our [guidelines](https://docs.google.com/document/d/1EMsVdfrDBAu0gmjWAUEs60q-fWaOmDB5oecY9d9pOlg/edit?usp=sharing).

    <a href="https://github.com/OWASP/owasp-mastg/issues?q=is%3Aopen+{id}" target="_blank">:material-github: Check our GitHub Issues for {id}</a>

    ## Initial Description or Hints

    {description}

{topics_section}

{refs_section}

    ## MASTG v1 Coverage

{mastg_v1_tests}
"""
    return banner

def get_tests_placeholder_banner(meta):
    id = meta.get('id')
    note = meta.get('note', None)
    weakness = meta.get('weakness', None)

    banner = f"""
!!! warning "Placeholder MASTG-TEST"

    This test hasn't been created yet and it's a **placeholder**. But you can check its status or start working on it yourself.
    If the issue has not yet been assigned, you can request to be assigned to it and submit a PR with the new content for that test by following our [guidelines](https://docs.google.com/document/d/1EMsVdfrDBAu0gmjWAUEs60q-fWaOmDB5oecY9d9pOlg/edit?pli=1&tab=t.0#heading=h.j1tiymiuocrm).

    <a href="https://github.com/OWASP/owasp-mastg/issues?q=is%3Aopen+{id}" target="_blank">:material-github: Check our GitHub Issues for {id}</a>

    If an issue doesn't exist yet, please create one and assign it to yourself or request to be assigned to it.

## Draft Description

{note}

For more details, check the associated weakness: @{weakness}

"""
    return banner

def get_v1_deprecated_tests_banner(meta):
    id = meta.get('id')
    covered_by = meta.get('covered_by', [])
    deprecation_note = meta.get('deprecation_note', "")

    if covered_by:
        covered_by = "\n".join([f"    - @{test}" for test in covered_by])
    else:
        covered_by = "    No tests are covering this weakness."

    banner = f"""
!!! danger "Deprecated Test"

    This test is **deprecated** and should not be used anymore. **Reason**: {deprecation_note}

    Please check the following MASTG v2 tests that cover this v1 test:

{covered_by}
"""
    return banner

def get_v1_refactor_tests_banner(meta, url, title):

    banner = f"""
!!! tip "This test will be updated soon"

    The test can be used in its current form, but it will receive a complete overhaul as part of the new <a href="https://docs.google.com/document/d/1veyzE4cVTSnIsKB1DOPUSMhjXow_MtJOtgHeo5HVoho/edit?tab=t.0#heading=h.ue8tn3i2ff0">OWASP MASTG v2 guidelines</a>.

    Help us out by submitting a PR for: <a href='{url}'>{title}</a>

    [:fontawesome-regular-paper-plane: Send Feedback](https://github.com/OWASP/owasp-mastg/discussions/categories/maswe-mastg-v2-beta-feedback)
"""
    return banner

def get_android_demo_buttons(page, artifacts_url):
    id = page.meta.get('id')

    page_uri = page.file.src_uri

    demo_folder = page_uri.replace("MASTG/demos/android/", "https://github.com/OWASP/owasp-mastg/blob/master/demos/android/").replace(f"/{id}.md", "/")

    banner = f"""
<a href="{artifacts_url}" class="md-button md-button--primary" style="margin: 5px; min-width: 12em;">:material-download:  Download {id} APK</a>
<a href="{demo_folder}" target='_blank' class="md-button md-button--primary" style="margin: 5px; min-width: 12em;">:material-folder-open:  Open {id} Folder</a>
<a href="https://github.com/cpholguera/MASTestApp-Android" target='_blank' class="md-button md-button--primary" style="margin: 5px; min-width: 12em;">:fontawesome-solid-compass-drafting: Build {id} APK</a>
"""
    return banner

def get_ios_demo_buttons(page, artifacts_url):
    id = page.meta.get('id')

    page_uri = page.file.src_uri

    demo_folder = page_uri.replace("MASTG/demos/ios/", "https://github.com/OWASP/owasp-mastg/blob/master/demos/ios/").replace(f"/{id}.md", "/")

    banner = f"""
<a href="{artifacts_url}" class="md-button md-button--primary" style="margin: 5px; min-width: 12em;">:material-download:  Download {id} IPA</a>
<a href="{demo_folder}" target='_blank' class="md-button md-button--primary" style="margin: 5px; min-width: 12em;">:material-folder-open:  Open {id} Folder</a>
<a href="https://github.com/cpholguera/MASTestApp-iOS" target='_blank' class="md-button md-button--primary" style="margin: 5px; min-width: 12em;">:fontawesome-solid-compass-drafting: Build {id} IPA</a>
"""
    return banner

def get_demos_placeholder_banner(meta):
    id = meta.get('id')
    note = meta.get('note', None)
    test = meta.get('test', None)

    banner = f"""
!!! warning "Placeholder MASTG-DEMO"

    This demo hasn't been created yet and it's a **placeholder**. But you can check its status or start working on it yourself.
    If the issue has not yet been assigned, you can request to be assigned to it and submit a PR with the new content for that demo by following our [guidelines](https://docs.google.com/document/d/1EMsVdfrDBAu0gmjWAUEs60q-fWaOmDB5oecY9d9pOlg/edit?pli=1&tab=t.0#heading=h.j1tiymiuocrm).

    <a href="https://github.com/OWASP/owasp-mastg/issues?q=is%3Aopen+{id}" target="_blank">:material-github: Check our GitHub Issues for {id}</a>

    If an issue doesn't exist yet, please create one and assign it to yourself or request to be assigned to it.

## Draft Description

{note}

For more details, check the associated test: @{test}

"""
    return banner

# https://www.mkdocs.org/dev-guide/plugins/#on_page_markdown
@mkdocs.plugins.event_priority(-40)
def on_page_markdown(markdown, page, config, **kwargs):
    path = page.file.src_uri

    banners = []

    if any(substring in path for substring in ["MASWE/"]):
        banners.append(beta_banner)

    if "MASWE/" in path and page.meta.get('status') == 'placeholder':
        banners.append(get_maswe_placeholder_banner(page.meta, config))

    if "MASTG/tests/" in path:
        if page.meta.get('status') == 'deprecated':
            banners.append(get_v1_deprecated_tests_banner(page.meta))
        if page.meta.get('status') == 'placeholder':
            banners.append(get_tests_placeholder_banner(page.meta))
        if link := config["issue_mapping"].get(page.meta.get("id")):
            banners.append(get_v1_refactor_tests_banner(page.meta, link[0], escape(link[1])))

    if "MASTG/demos/android/" in path and not page.meta.get('status') == 'placeholder':
        banners.append(get_android_demo_buttons(page, config["artifacts_url_android"]))

    if "MASTG/demos/ios/" in path and not page.meta.get('status') == 'placeholder':
        banners.append(get_ios_demo_buttons(page, config["artifacts_url_ios"]))

    if "MASTG/demos/" in path and page.meta.get('status') == 'placeholder':
        banners.append(get_demos_placeholder_banner(page.meta))

    if banners:
        markdown = "\n\n".join(banners) + "\n\n" + markdown

    return markdown


def on_config(config):

    config["issue_mapping"] = github_api.get_issues_for_test_refactors()
    config["artifacts_url_ios"] = github_api.get_latest_successful_run("build-ios-demos.yml")
    config["artifacts_url_android"] = github_api.get_latest_successful_run("build-android-demos.yml")

    # If the artifacts URL couldn't be fetched due to API issues, provide a generic URL
    if not config["artifacts_url_android"]:
        config["artifacts_url_android"] = "https://github.com/OWASP/owasp-mastg/actions/workflows/build-android-demos.yml"

    if not config["artifacts_url_ios"]:
        config["artifacts_url_ios"] = "https://github.com/OWASP/owasp-mastg/actions/workflows/build-ios-demos.yml"

    config["v1_tests_data"] = get_v1_tests_data()

    return config