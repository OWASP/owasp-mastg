import logging
import mkdocs.plugins

log = logging.getLogger('mkdocs')

# This plugin extracts the ID and component_type from the filename if no ID is defined
# This is only the case for older tests (ID < 200)
@mkdocs.plugins.event_priority(30)
def on_page_markdown(markdown, page, config, **kwargs):
    path = page.file.src_uri

    if any(keyword in path for keyword in ["MASTG-TEST-", "MASTG-TOOL-", "MASTG-TECH-", "MASTG-APP-", "MASTG-DEMO-", "MASTG-BEST-"]):
        try:
            item_id = path.split('/')[-1].split('.')[0]
        except:
            raise Exception(f"Unable to extract ID from path: '{path}'")

        if item_id != page.meta.get('id', item_id):
            raise Exception(f"Metadata ID doesn't match filename for {path}: \n\tMetadata: {page.meta.get('id')}")

        page.meta['id'] = item_id
        page.meta['component_type'] = item_id.split("-")[1]

    if "MASWE-" in path:
        if not page.meta.get("id", None):
            raise Exception(f"MASWE without ID: '{path}'")
        page.meta['component_type'] = "maswe"
