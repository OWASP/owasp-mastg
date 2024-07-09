import logging
import mkdocs.plugins

log = logging.getLogger('mkdocs')

# https://www.mkdocs.org/dev-guide/plugins/#on_page_markdown
@mkdocs.plugins.event_priority(-50)
def on_page_markdown(markdown, page, **kwargs):
    path = page.file.src_uri

    if "MASWE/" in path:

        tags = page.meta.get('tags', [])

        if page.meta.get('platform'):
            if type(page.meta.get('platform')) == str:
                tags.append(page.meta.get('platform'))
            elif type(page.meta.get('platform')) == list:
                for platform in page.meta.get('platform'):
                    tags.append(platform)
        if page.meta.get('profiles'):
            for profile in page.meta.get('profiles', []):
                tags.append(profile)
        
        if page.meta.get('masvs-v2'):
            for masvs_v2 in page.meta.get('masvs-v2', []):
                tags.append(masvs_v2)
        
        page.meta['tags'] = tags

    return markdown
