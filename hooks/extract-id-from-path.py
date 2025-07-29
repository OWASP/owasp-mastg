import logging
import os
import mkdocs.plugins

log = logging.getLogger('mkdocs')

# This hook extracts the ID and component_type from the filename if no ID is defined
# This is only the case for older tests (ID < 200)
@mkdocs.plugins.event_priority(-30)
def on_page_markdown(markdown, page, config, **kwargs):
    path = page.file.src_uri
    filename = os.path.basename(path)

    if any(keyword in filename for keyword in ["MASTG-KNOW-", "MASTG-TEST-", "MASTG-TOOL-", "MASTG-TECH-", "MASTG-APP-", "MASTG-DEMO-", "MASTG-BEST-", "MASWE-"]):
        try:
            # Extract the item_id by removing the file extension and handling possible extra dots in filename
            item_id, _ = os.path.splitext(os.path.basename(path))
        except Exception as e:
            raise Exception(f"Unable to extract ID from path: '{path}'") from e

        if item_id != page.meta.get('id', item_id):
            raise Exception(f"Metadata ID doesn't match filename for {path}: \n\tMetadata: {page.meta.get('id')}")

        page.meta['id'] = item_id

        # Assign component_type and icon. icon will be used to automatically add icons to navigation
        component_type = item_id.split("-")[-2]
        page.meta['component_type'] = component_type
        page.meta['icon'] = config.get('theme').get('icon').get('tag', {}).get(component_type.lower())

    if "MASWE-" in filename:
        if not page.meta.get("id", None):
            raise Exception(f"MASWE without ID: '{path}'")

    return markdown