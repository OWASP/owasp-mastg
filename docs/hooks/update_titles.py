import logging
import mkdocs.plugins

log = logging.getLogger('mkdocs')

# https://www.mkdocs.org/dev-guide/plugins/#on_page_markdown
@mkdocs.plugins.event_priority(-50)
def on_page_markdown(markdown, page, **kwargs):
    path = page.file.src_uri
    title_prefix_map = {
        'weakness.md': 'Weakness: ',
        'test.md': 'Test: ',
        'demo.md': 'Demo: '
    }

    for filename, prefix in title_prefix_map.items():
        if path.endswith(filename):
            page.meta['title'] = f"{prefix}{page.meta.get('title', '')}"
            break

    return markdown
