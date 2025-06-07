import logging
import mkdocs.plugins

log = logging.getLogger('mkdocs')

checklists_banner = """
!!! info "Checklist Updates Ongoing (June 2025)"
    The checklists now contain the new [MAS profiles](https://docs.google.com/document/d/1paz7dxKXHzAC9MN7Mnln1JiZwBNyg7Gs364AJ6KudEs/edit?usp=sharing) for each test.
    
    We are currently working on updating this view for a better user experience.
"""

# https://www.mkdocs.org/dev-guide/plugins/#on_page_markdown
@mkdocs.plugins.event_priority(-50)
def on_page_markdown(markdown, page, **kwargs):
    path = page.file.src_uri

    if "checklists/MASVS-" in path:
        markdown = "\n" + checklists_banner + "\n\n" + markdown

    return markdown
