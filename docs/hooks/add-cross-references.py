import logging
import yaml
import mkdocs.plugins

log = logging.getLogger('mkdocs')

def load_cross_references():
    with open("cross_references.yaml", 'r') as f:
        return yaml.safe_load(f)

cross_references = load_cross_references()

def add_cross_references_to_metadata(page):
    page_id = page.meta.get('id')
    if not page_id:
        return

    if page_id in cross_references:
        if 'tests' in cross_references[page_id]:
            page.meta['tests'] = cross_references[page_id]['tests']
        if 'demos' in cross_references[page_id]:
            page.meta['demos'] = cross_references[page_id]['demos']

def add_markdown_sections(markdown, page):
    sections = []

    if 'tests' in page.meta and page.meta['tests']:
        sections.append("## Tests\n\n" + "\n".join([f"- [{test}](/MASTG/tests-beta/android/MASVS-PRIVACY/{test})" for test in page.meta['tests']]))

    if 'demos' in page.meta and page.meta['demos']:
        sections.append("## Demos\n\n" + "\n".join([f"- [{demo}](/MASTG/demos/android/MASVS-PRIVACY/{demo}/{demo})" for demo in page.meta['demos']]))

    if sections:
        markdown += "\n\n" + "\n\n".join(sections)

    return markdown

@mkdocs.plugins.event_priority(-50)
def on_page_markdown(markdown, page, **kwargs):
    add_cross_references_to_metadata(page)
    markdown = add_markdown_sections(markdown, page)
    return markdown
