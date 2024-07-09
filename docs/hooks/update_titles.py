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
    
    if any(keyword in path for keyword in ["MASTG-TEST-", "MASTG-TOOL-", "MASTG-TECH-", "MASTG-APP-", "MASTG-DEMO-"]):
        # the component ID is the file basename without the extension
        page.meta['id'] = path.split('/')[-1].split('.')[0]
        page.meta['title'] = f"{page.meta['id']}: {page.meta.get('title', '')}"

    if page.meta.get('id') and "MASWE" in page.meta.get('id'): 
        page.meta['title'] = f"{page.meta.get('id')}: {page.meta.get('title', '')}"
    
    return markdown
