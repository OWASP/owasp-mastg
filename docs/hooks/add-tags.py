import logging
import mkdocs.plugins

log = logging.getLogger('mkdocs')

# https://www.mkdocs.org/dev-guide/plugins/#on_page_markdown
# mkdocs/tags runs at -50 so this has to be called before -50
@mkdocs.plugins.event_priority(-49)
def on_page_markdown(markdown, page, **kwargs):
    path = page.file.src_uri

    tags = page.meta.get('tags', [])

    if page.meta.get('masvs_category'):
        tags.append(page.meta.get('masvs_category'))

    if page.meta.get('platform'):
        if type(page.meta.get('platform')) == str:
            tags.append(page.meta.get('platform'))
        elif type(page.meta.get('platform')) == list:
            for platform in page.meta.get('platform'):
                tags.append(platform)
    if page.meta.get('profiles'):
        for profile in page.meta.get('profiles', []):
            tags.append(profile)

    if page.meta.get('weakness'):
        tags.append(page.meta.get('weakness'))
    if page.meta.get('test'):
        tags.append(page.meta.get('test'))
    
    if mappings:=page.meta.get('mappings'):
        if masvs_v2:=mappings.get('masvs-v2'):
            for masvs_id in masvs_v2:
                tags.append(masvs_id)
    
    # TODO - This is only for the MASTG v1 tests; remove this once all pages have been updated to use mappings
    if masvs_v2:=page.meta.get('masvs_v2_id'):
        for masvs_id in masvs_v2:
            tags.append(masvs_id)
    if masvs_v1:=page.meta.get('masvs_v1_id'):
        for masvs_id in masvs_v1:
            tags.append(masvs_id)
    # END TODO

    if page.meta.get('status'):
        if page.meta.get('status') == 'placeholder':
            tags.append('placeholder')

    if page.meta.get('status'):
        if page.meta.get('status') == 'deprecated':
            tags.append('deprecated')
    
    page.meta['tags'] = tags

    return markdown
