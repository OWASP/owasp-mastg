import logging
import mkdocs.plugins
import yaml
import glob
import os
import re

log = logging.getLogger('mkdocs')

# https://www.mkdocs.org/dev-guide/plugins/#on_page_markdown
# mkdocs/tags runs at -50 so this has to be called before -50
@mkdocs.plugins.event_priority(-49)
def _on_page_markdown_2(markdown, page, **kwargs):

    tags = page.meta.get('tags', [])

    if meta_platform := page.meta.get('platform'):
        if type(meta_platform) == str:
            tags.append(meta_platform)
        elif type(meta_platform) == list:
            for platform in meta_platform:
                tags.append(platform)

    for profile in page.meta.get('profiles', []):
        tags.append(profile)

    # If any of these tags don't exist, they will be stripped automatically at the end of the function
    tags.append(page.meta.get("masvs_category"))

    if page.meta.get("test"):
        tags.append("placeholder-tag-test")
    tags.append(page.meta.get("component_type", "").lower())

    # If there is a weakness, add the place holder. This is then picked up by the tag builder and styled correctly
    # The placeholder is swapped to the correct value later
    if page.meta.get("weakness"):
        tags.append("placeholder-tag-maswe")

    # TODO - This is only for the MASTG v1 tests; remove this once all pages have been updated to use mappings
    tags += page.meta.get("masvs_v1_id", [])
    tags += [tag.lower() for tag in page.meta.get("masvs_v2_id", [])]
    # END TODO

    if mappings:=page.meta.get('mappings'):
        if masvs_v2:=mappings.get('masvs-v2'):
            for masvs_id in masvs_v2:
                tags.append(masvs_id.lower())

    meta_status = page.meta.get('status')
    if meta_status in ["placeholder", "deprecated"]:
        tags.append(meta_status)

    page.meta['tags'] = [tag for tag in tags if tag]

    return markdown

# Run again after the tags have been rendered
# This way, the correct value gets picked up for the search indexer
@mkdocs.plugins.event_priority(-51)
def _on_page_markdown_1(markdown, page, **kwargs):

    tags = page.meta.get('tags', [])

    if weakness := page.meta.get("weakness"):
        tags.remove("placeholder-tag-maswe")
        tags.append(weakness)

    if test := page.meta.get("test"):
        tags.remove("placeholder-tag-test")
        tags.append(test)

    page.meta['tags'] = [tag for tag in tags if tag]


on_page_markdown = mkdocs.plugins.CombinedEvent(_on_page_markdown_1, _on_page_markdown_2)

# The tag renderer used the placeholder value, so we have to convert it to the actual value
# At the same time, we're making some of the URLs more purposeful
@mkdocs.plugins.event_priority(-51)
def on_post_page(output, page, config):

    # Replace maswe placeholder with actual value
    if weakness := page.meta.get("weakness"):
        output = output.replace("placeholder-tag-maswe", weakness)

    if test := page.meta.get("test"):
        output = output.replace("placeholder-tag-test", test)

    # By default, tags link to the main tags page. These substitutions make the tag links more useful
    # Transform URLs for MASWE tags to a more purposeful format.
    # Matches URLs like '/tags/#tag:MASWE-<number>' and replaces them with '/MASWE/<category>/MASWE-<number>',
    # where <category> is determined from the 'hook_add_tags_maswe_data' mapping in the config.
    output = re.sub(r'/tags/#tag:(MASWE-\d+)"', lambda x: f'/MASWE/{config["hook_add_tags_maswe_data"].get(x.group(1))}/{x.group(1)}"' , output)
    output = re.sub(r'/tags/#tag:test"', '/MASTG/tests/"' , output)
    output = re.sub(r'/tags/#tag:maswe"', '/MASWE/"' , output)
    output = re.sub(r'/tags/#tag:demo"', '/MASTG/demos/"' , output)
    output = re.sub(r'/tags/#tag:tool"', '/MASTG/tools/"' , output)
    output = re.sub(r'/tags/#tag:app"', '/MASTG/apps/"' , output)
    output = re.sub(r'/tags/#tag:best"', '/MASTG/best-practices/"' , output)
    output = re.sub(r'/tags/#tag:tech"', '/MASTG/techniques/"' , output)
    output = re.sub(r'/tags/#tag:network"', '/MASTG/tests/#network"' , output)
    output = re.sub(r'/tags/#tag:l1"', '/MASTG/tests/#l1"' , output)
    output = re.sub(r'/tags/#tag:l2"', '/MASTG/tests/#l2"' , output)
    output = re.sub(r'/tags/#tag:r"', '/MASTG/tests/#r"' , output)
    output = re.sub(r'/tags/#tag:p"', '/MASTG/tests/#p"' , output)
    output = re.sub(r'/tags/#tag:(MASTG-TEST-\d+)"', lambda x: f'/MASTG/tests/{config["hook_add_tags_test_data"].get(x.group(1).upper())}/{x.group(1).upper()}"' , output)
    
    path = page.file.src_uri
    # Some context-specific changes
    if "MASTG/0x" in path:
        # These are the MASTG testing pages
        # TODO - Temp hack until after MASVS page restructure
        mapping = {
            "MASVS-STORAGE": "/MASVS/05-MASVS-STORAGE/",
            "MASVS-CRYPTO": "/MASVS/06-MASVS-CRYPTO/",
            "MASVS-AUTH": "/MASVS/07-MASVS-AUTH/",
            "MASVS-NETWORK": "/MASVS/08-MASVS-NETWORK/",
            "MASVS-PLATFORM": "/MASVS/09-MASVS-PLATFORM/",
            "MASVS-CODE": "/MASVS/10-MASVS-CODE/",
            "MASVS-RESILIENCE": "/MASVS/11-MASVS-RESILIENCE/",
            "MASVS-PRIVACY": "/MASVS/12-MASVS-PRIVACY/",
        }
        output = re.sub(r'/tags/#tag:(masvs-[^"]*)"', lambda x: f'{mapping.get(x.group(1).upper())}"' , output)
    else:
        output = re.sub(r'/tags/#tag:(masvs-[^"]*)"', lambda x: f'/MASVS/controls/{x.group(1).upper()}"' , output)
    
    
    # TODO - These are disabled currently, as multiple pages have android/ios labels and they shouldn't always to go the tests page
    # output = re.sub(r'/tags/#tag:android"', '/MASTG/tests/#android"' , output)
    # output = re.sub(r'/tags/#tag:ios"', '/MASTG/tests/#ios"' , output)

    # A final switch for things like the main tags page or other places where tags were collected
    output = output.replace("placeholder-tag-maswe", "MASWE")
    output = output.replace("placeholder-tag-test", "TEST")

    return output

def get_maswe_data():

    data = {}
    # Each test has an ID which is the filename
    for file in glob.glob("docs/MASWE/**/MASWE-*.md", recursive=True):
        path_parts = os.path.split(file)
        id = os.path.splitext(path_parts[1])[0]
        masvs_category = os.path.split(path_parts[0])[1]
        data[id] = masvs_category

    return data


def get_test_data():
    data = {}
    # Each test has an ID which is the filename
    for file in glob.glob("docs/MASTG/tests/**/MASTG-TEST-*.md", recursive=True):
        path_parts = file.split('/')
        id = os.path.splitext(path_parts[-1])[0]
        masvs_category = f"{path_parts[-3]}/{path_parts[-2]}"
        data[id] = masvs_category
    return data

def on_config(config):

    config["hook_add_tags_maswe_data"] = get_maswe_data()
    config["hook_add_tags_test_data"] = get_test_data()

