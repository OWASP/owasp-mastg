import logging
import mkdocs.plugins

log = logging.getLogger('mkdocs')


# This plugin is responsible for adding the ID to the title and setting the page's icon
@mkdocs.plugins.event_priority(-49)
def on_page_markdown(markdown, page, config, **kwargs):
    path = page.file.src_uri

    if item_id := page.meta.get("id", None):

        page.meta['title'] = f"{item_id}: {page.meta.get('title', '')}"
        page.meta['hide'] = ['toc']

        icons = config.get('theme').get('icon').get('tag', {})
        page.meta['icon'] = icons.get(page.meta.get('component_type'))
