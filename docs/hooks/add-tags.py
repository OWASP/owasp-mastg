import logging
import mkdocs.plugins

log = logging.getLogger('mkdocs')

# https://www.mkdocs.org/dev-guide/plugins/#on_page_markdown
# mkdocs/tags runs at -50 so this has to be called before -50
@mkdocs.plugins.event_priority(-49)
def on_page_markdown(markdown, page, **kwargs):

    tags = page.meta.get('tags', [])

    if meta_platform := page.meta.get('platform'):
        if type(meta_platform) == str:
            tags.append(meta_platform)
        elif type(meta_platform) == list:
            for platform in meta_platform:
                tags.append(platform)

    for profile in page.meta.get('profiles', []):
        tags.append(profile)

    tags.append(page.meta.get("masvs_category"))
    tags.append(page.meta.get("component_type"))
    tags.append(page.meta.get("weakness"))
    tags.append(page.meta.get("test"))

    # TODO - This is only for the MASTG v1 tests; remove this once all pages have been updated to use mappings
    tags += page.meta.get("masvs_v1_id", [])
    tags += page.meta.get("masvs_v2_id", [])
    # END TODO

    if mappings:=page.meta.get('mappings'):
        if masvs_v2:=mappings.get('masvs-v2'):
            for masvs_id in masvs_v2:
                tags.append(masvs_id)

    meta_status = page.meta.get('status')
    if meta_status in ["placeholder", "deprecated"]:
        tags.append(meta_status)

    page.meta['tags'] = [tag.upper() for tag in tags if tag]

    return markdown
