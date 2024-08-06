import logging
import yaml
import mkdocs.plugins
import glob, os
from collections import defaultdict

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
                log.warn("No frontmatter in " + file)

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

def get_mastg_v1_coverage(meta):
    mappings = meta.get('mappings', '')

    if mappings:
        mastg_v1_tests_metadata, mastg_v1_mapping = get_v1_tests_data()

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

def get_info_banner(meta):

    id = meta.get('id')

    refs = meta.get('refs', None)
    refs_section = ""
    if refs:
        refs_section = "    ## References\n\n"
        refs_section += "\n".join([f"    - <{ref}>" for ref in refs])

    draft_info = meta.get('draft', None)

    description = draft_info.get('description', None)

    if draft_info.get('note', None):
        description += "\n\n" + "    > Note: " + draft_info.get('note', None) + "\n"

    topics = draft_info.get('topics', None)
    topics_section = ""
    if topics:
        topics_section = "    ## Relevant Topics\n\n"
        topics_section += "\n".join([f"    - {topic}" for topic in topics])
    
    mastg_v1_tests = get_mastg_v1_coverage(meta)

    info_banner = f"""
!!! warning "Draft Weakness"

    This weakness hasn't been created yet and it's in **draft**. But you can check its status or start working on it yourself.
    If the issue has not yet been assigned, you can request to be assigned to it and submit a PR with the new content for that weakness by following our [guidelines](https://docs.google.com/document/d/1EMsVdfrDBAu0gmjWAUEs60q-fWaOmDB5oecY9d9pOlg/edit?usp=sharing).

    <a href="https://github.com/OWASP/owasp-mastg/issues?q=is%3Aissue+is%3Aopen+{id}" target="_blank">:material-github: Check our GitHub Issues for {id}</a>
    
    ## Initial Description or Hints

    {description}
    
{topics_section}
    
{refs_section}

    ## MASTG v1 Coverage

{mastg_v1_tests}
"""
    return info_banner

# https://www.mkdocs.org/dev-guide/plugins/#on_page_markdown
@mkdocs.plugins.event_priority(-50)
def on_page_markdown(markdown, page, **kwargs):
    path = page.file.src_uri

    banners = []

    if any(substring in path for substring in ["MASWE/", "MASTG/tests-beta/", "MASTG/demos/"]):
        banners.append(beta_banner)
    
    if "MASWE/" in path and page.meta.get('status') == 'draft':
        banners.append(get_info_banner(page.meta))

    if banners:
        markdown = "\n\n".join(banners) + "\n\n" + markdown

    return markdown
