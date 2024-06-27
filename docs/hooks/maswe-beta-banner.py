import logging
import mkdocs.plugins

log = logging.getLogger('mkdocs')

beta_banner = """
!!! example "BETA"
    This is a beta version of the [MASWE (Mobile Application Security Weakness Enumeration)](https://mas.owasp.org/MASWE/). The content is still under development and may change in terms of structure, IDs and content.
    Your feedback and questions are welcome! Please post them to [MASWE Feedback](https://github.com/OWASP/owasp-mastg/discussions/categories/maswe-feedback).
"""

# https://www.mkdocs.org/dev-guide/plugins/#on_page_markdown
@mkdocs.plugins.event_priority(-50)
def on_page_markdown(markdown, page, **kwargs):
    path = page.file.src_uri

    if "MASWE/" in path:
        markdown = f"{beta_banner}\n\n{markdown}"

    return markdown
