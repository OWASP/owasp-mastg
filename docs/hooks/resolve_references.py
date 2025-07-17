import logging
import re
import mkdocs.plugins
import os
from glob import glob
import yaml
from functools import lru_cache

log = logging.getLogger('mkdocs')

mapping = {"TECH":{}, "TOOL":{}, "TEST": {}, "APP": {}, "MASWE": {}, "MASVS": {}, "DEMO": {}, "BEST": {}}

@mkdocs.plugins.event_priority(-50)
def on_page_markdown(markdown, page, config, **kwargs):
    path = page.file.src_uri

    icons = config.get('resolve_ref_icons')
    icons_for_text = config.get('resolve_ref_icons_for_text')

    pageRefs = {"TECH": [], "TOOL": [], "TEST": [], "APP": [], "MASWE": [], "MASVS": [], "DEMO": [], "BEST": []}

    def replaceReference(match):
        refType = match.group(2)

        pageRefs[refType].append(match.group(1))

        if not match in mapping[refType]:
            target = getTargetForRef(match.group(1), path)
            mapping[refType][match] = target

        icon = icons_for_text.get(refType, ":octicons-question-24: ")

        return f"_[{icon}{mapping[refType][match]['title']}]({mapping[refType][match]['file']} \"{refType}\")_"

    def replaceReferenceMASWE(match):
        refType = "MASWE"

        pageRefs[refType].append(match.group(1))

        if not match in mapping[refType]:
            target = getTargetForRef(match.group(1), path)
            mapping[refType][match] = target

        icon = icons_for_text.get(refType, ":octicons-question-24: ")
        return f"_[{icon}{mapping[refType][match]['title']}]({mapping[refType][match]['file']} \"{refType}\")_"

    def replaceReferenceMASVS(match):
        refType = "MASVS"

        pageRefs[refType].append(match.group(1))

        if not match in mapping[refType]:
            target = getTargetForRef(match.group(1), path)
            mapping[refType][match] = target

        icon = icons_for_text.get(refType, ":octicons-question-24: ")
        return f"_[{icon}{mapping[refType][match]['title']}]({mapping[refType][match]['file']} \"{refType}\")_"


    updated_markdown = re.sub(r'@(MASTG-(TECH|TOOL|TEST|APP|DEMO|BEST)-\d{3,})', replaceReference, markdown)
    updated_markdown = re.sub(r'@(MASWE-\d{3,})', replaceReferenceMASWE, updated_markdown)
    updated_markdown = re.sub(r'@(MASVS-\w+)', replaceReferenceMASVS, updated_markdown)

    page.meta["tools"] = list(set(pageRefs["TOOL"]))
    page.meta["techniques"] = list(set(pageRefs["TECH"]))

    return updated_markdown

@lru_cache(maxsize=None)
def getFileContent(path):
    with open(path, 'r') as f:
        content = f.read()
        metadata = next(yaml.safe_load_all(content))

        return {"title": metadata['title']}

@lru_cache(maxsize=None)
def getTargetForRef(id, path):
    searchFor = f'./docs/**/{id}.md'

    files = glob(searchFor, recursive=True)

    if not len(files):
        log.error("Unknown reference: " + id)
        return {"file": "ERROR", "title": "error"}

    file_url =   os.path.relpath(files[0], "./docs/" + os.path.dirname(path))
    data = getFileContent(files[0])
    data["file"] = file_url
    return data

def on_config(config):
    config["resolve_ref_icons"] = config.get('theme').get('icon').get('tag', {})
    config["resolve_ref_icons_for_text"] = {key.upper(): f":{value.replace('/', '-')}: " for key, value in config["resolve_ref_icons"].items()}