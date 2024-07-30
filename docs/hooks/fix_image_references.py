import logging
import mkdocs.plugins
import os
import re
log = logging.getLogger('mkdocs')

@mkdocs.plugins.event_priority(-50)
def on_page_content(html, page, config, files):
    path = page.file.src_uri
    # title_prefix_map = {}

    def fixURL(match):
        # relPath = os.path.relpath()
        # relPath = os.path.relpath("./" + match.group(1), os.path.dirname(path))

        # log.error(path)

        # log.error(match.group(1))
        # log.error(relPath)

        # path = MASWE/... or MASTG/... so take the first part and put in before the /Images match
        projects = ["MASTG", "MASWE", "MASVS"]
        project = path.split("/")[0]
        project = ""
        img_path = match.group(1)
        if not project in projects:
            project = "assets"
            img_path = img_path.replace("/Images", "")

        return f'<img src="/{project}{img_path}"'

    updated_html = re.sub(r'<img src="(/Images/[^"]+)"', fixURL, html)
    return updated_html

     


@mkdocs.plugins.event_priority(-50)
def on_page_markdown(markdown, page, **kwargs):
    path = page.file.src_uri

    def fixURL(match):
        # relPath = os.path.relpath()
        relPath = os.path.relpath("./" + match.group(1), os.path.dirname(path))

        log.error(match.group(1))
        log.error(relPath)

        return f"({relPath})"

    updated_markdown = re.sub(r'\((Images/[^\)]+)\)', fixURL, markdown)
    return updated_markdown
