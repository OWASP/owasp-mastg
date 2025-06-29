import logging
import mkdocs.plugins

log = logging.getLogger('mkdocs')

# This hook extracts the ID and component_type from the filename if no ID is defined
# This is only the case for older tests (ID < 200)
@mkdocs.plugins.event_priority(-30)
def on_page_markdown(markdown, page, config, **kwargs):
    path = page.file.src_uri

    if any(keyword in path for keyword in ["MASTG-TEST-", "MASTG-TOOL-", "MASTG-TECH-", "MASTG-APP-", "MASTG-DEMO-", "MASTG-BEST-", "MASWE-"]):
        try:
            item_id = path.split('/')[-1].split('.')[0]
        except:
            raise Exception(f"Unable to extract ID from path: '{path}'")

        if item_id != page.meta.get('id', item_id):
            raise Exception(f"Metadata ID doesn't match filename for {path}: \n\tMetadata: {page.meta.get('id')}")

        page.meta['id'] = item_id

        # Assign component_type and icon. icon will be used to automatically add icons to navigation
        component_type = item_id.split("-")[-2]
        page.meta['component_type'] = component_type
        page.meta['icon'] = config.get('theme').get('icon').get('tag', {}).get(component_type.lower())

    if "MASWE-" in path:
        if not page.meta.get("id", None):
            raise Exception(f"MASWE without ID: '{path}'")

    return markdown