import logging
import mkdocs.plugins

log = logging.getLogger('mkdocs')

def set_page_icon(page, config, component_type=None):
    icons = config.get('theme').get('icon').get('tag', {})
    page.meta['icon'] = icons.get(component_type, None)
    page.meta['tags'] = [component_type] + page.meta.get('tags', [])

# https://www.mkdocs.org/dev-guide/plugins/#on_page_markdown
@mkdocs.plugins.event_priority(-49)
def on_page_markdown(markdown, page, config, **kwargs):
    path = page.file.src_uri

    if any(keyword in path for keyword in ["MASTG-TEST-", "MASTG-TOOL-", "MASTG-TECH-", "MASTG-APP-", "MASTG-DEMO-", "MASTG-BEST-"]):
        # TODO the component ID is the file basename without the extension; ensure that all components have id in the future
        try:
            item_id = path.split('/')[-1].split('.')[0]
            actual_id = page.meta.get('id')
            if not item_id == actual_id:
                print("Error: ", item_id, actual_id)
            page.meta['id'] = item_id

            component_type = page.meta['id'].split('-')[1].lower()
            page.meta['title'] = f"{page.meta['id']}: {page.meta.get('title', '')}"
            set_page_icon(page, config, component_type)
        except:
            raise Exception(f"Unable to extract ID from path: '{path}'")

        page.meta['hide'] = ['toc']

    if "MASWE" in page.meta.get('id', ''):
        page.meta['title'] = f"{page.meta.get('id')}: {page.meta.get('title', '')}"
        component_type = "maswe"
        set_page_icon(page, config, component_type)

        page.meta['hide'] = ['toc']

    return markdown
