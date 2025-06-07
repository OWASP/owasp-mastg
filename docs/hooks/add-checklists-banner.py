import logging
import mkdocs.plugins

log = logging.getLogger('mkdocs')

checklists_banner = """
!!! info "Temporary Checklist"
    This checklist contains the **old MASVS v1 verification levels (L1, L2 and R)** which we are currently reworking into "security testing profiles". The levels were assigned according to the MASVS v1 ID that the test was previously covering and might differ in the upcoming version of the MASTG and MAS Checklist.

    For the upcoming of the MASTG version we will progressively split the MASTG tests into smaller tests, the so-called "atomic tests" and assign the new [MAS profiles](https://docs.google.com/document/d/1paz7dxKXHzAC9MN7Mnln1JiZwBNyg7Gs364AJ6KudEs/edit?usp=sharing) to their respective MASWE weaknesses.
"""

# https://www.mkdocs.org/dev-guide/plugins/#on_page_markdown
@mkdocs.plugins.event_priority(-50)
def on_page_markdown(markdown, page, **kwargs):
    path = page.file.src_uri

    if "checklists/MASVS-" in path:
        markdown = "\n" + checklists_banner + "\n\n" + markdown

    return markdown
