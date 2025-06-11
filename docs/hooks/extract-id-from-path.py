import logging
import mkdocs.plugins

log = logging.getLogger('mkdocs')

# This plugin extracts the ID from the filename if no ID is defined
# This is only the case for older tests (ID < 200)
@mkdocs.plugins.event_priority(-49)
def on_page_markdown(markdown, page, config, **kwargs):
    path = page.file.src_uri

    if any(keyword in path for keyword in ["MASTG-TEST-", "MASTG-TOOL-", "MASTG-TECH-", "MASTG-APP-", "MASTG-DEMO-", "MASTG-BEST-"]):
        try:
            item_id = path.split('/')[-1].split('.')[0]
        except:
            raise Exception(f"Unable to extract ID from path: '{path}'")

        if item_id != page.meta.get('id', item_id):
            raise Exception(f"Metadata ID doesn't match filename for {path}")

        page.meta['id'] = item_id
