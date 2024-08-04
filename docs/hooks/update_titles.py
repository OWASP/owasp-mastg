import logging
import mkdocs.plugins

log = logging.getLogger('mkdocs')

# https://www.mkdocs.org/dev-guide/plugins/#on_page_markdown
@mkdocs.plugins.event_priority(-50)
def on_page_markdown(markdown, page, config, **kwargs):
    path = page.file.src_uri
    
    if any(keyword in path for keyword in ["MASTG-TEST-", "MASTG-TOOL-", "MASTG-TECH-", "MASTG-APP-", "MASTG-DEMO-"]):
        # the component ID is the file basename without the extension
        page.meta['id'] = path.split('/')[-1].split('.')[0]
        page.meta['title'] = f"{page.meta['id']}: {page.meta.get('title', '')}"

        icons = config.get('theme').get('icon').get('tag', {})
        
        # Set page icon: https://squidfunk.github.io/mkdocs-material/reference/#setting-the-page-icon
        for key, value in icons.items():
            if key.upper() in page.meta['id']:
                icon = value
                # icon = value.strip().replace('-', '/', 1)[1:-1]
                page.meta['icon'] = icon
                page.meta['tags'] = [key] + page.meta.get('tags', [])
                break

    if page.meta.get('id') and "MASWE" in page.meta.get('id'): 
        page.meta['title'] = f"{page.meta.get('id')}: {page.meta.get('title', '')}"
    
    return markdown
