import logging
import mkdocs.plugins

log = logging.getLogger('mkdocs')


# This hook is responsible for adding the ID to the title and setting the page's icon
@mkdocs.plugins.event_priority(-49)
def on_page_markdown(markdown, page, config, **kwargs):

    if item_id := page.meta.get("id", None):

        # For some files, the title == id (e.g. checklists pages)
        if not item_id == page.meta.get("title", None):

            page.meta['title'] = f"{item_id}: {page.meta.get('title', '')}"
            page.meta['hide'] = ['toc']

    return markdown