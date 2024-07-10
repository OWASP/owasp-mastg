import logging
import mkdocs.plugins

log = logging.getLogger('mkdocs')

beta_banner = """
!!! example "BETA"
    This content is in **beta** and still under active development, so it is subject to change any time (e.g. structure, IDs, content, URLs, etc.).
    
    [:fontawesome-regular-paper-plane: Send Feedback](https://github.com/OWASP/owasp-mastg/discussions/categories/maswe-mastg-v2-beta-feedback)
"""

# https://www.mkdocs.org/dev-guide/plugins/#on_page_markdown
@mkdocs.plugins.event_priority(-50)
def on_page_markdown(markdown, page, **kwargs):
    path = page.file.src_uri

    if any(substring in path for substring in ["MASWE/", "MASTG/tests-beta/", "MASTG/demos/"]):
        markdown = f"{beta_banner}\n\n{markdown}"

    return markdown
