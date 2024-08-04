import logging
import re
import mkdocs.plugins
import os
from glob import glob
import yaml
log = logging.getLogger('mkdocs')

mapping = {"TECH":{}, "TOOL":{}, "TEST": {}, "APP": {}, "MASWE": {}, "MASVS": {}, "DEMO": {}}

@mkdocs.plugins.event_priority(-50)
def on_page_markdown(markdown, page, **kwargs):
    path = page.file.src_uri

    pageRefs = {"TECH":[], "TOOL":[], "TEST": [], "APP": [], "MASWE": [], "MASVS": [], "DEMO": []}
    def replaceReference(match):
        refType = match.group(2)

        pageRefs[refType].append(match.group(1))

        if not match in mapping[refType]:
            target = getTargetForRef(match.group(1), path)
            mapping[refType][match] = target

        icon = ""
        if refType == "TOOL":
            icon = ":octicons-tools-24: "
        elif refType == "TEST":
            icon = ":octicons-codescan-checkmark-24: "
        elif refType == "APP":
            icon = ":octicons-code-square-24: "
        elif refType == "DEMO":
            icon = ":material-flask-outline: "
        elif refType == "TECH":
            icon = ":material-magic-staff: "

        return f"_[{icon}{mapping[refType][match]['title']}]({mapping[refType][match]['file']})_"

    def replaceReferenceMASWE(match):
        refType = "MASWE"

        pageRefs[refType].append(match.group(1))

        if not match in mapping[refType]:
            target = getTargetForRef(match.group(1), path)
            mapping[refType][match] = target

        icon = ":material-skull-scan-outline: "
        return f"_[{icon}{mapping[refType][match]['title']}]({mapping[refType][match]['file']})_"

    def replaceReferenceMASVS(match):
        refType = "MASVS"

        pageRefs[refType].append(match.group(1))

        if not match in mapping[refType]:
            target = getTargetForRef(match.group(1), path)
            mapping[refType][match] = target

        icon = ":simple-owasp: "
        return f"_[{icon}{mapping[refType][match]['title']}]({mapping[refType][match]['file']})_"


    updated_markdown = re.sub(r'@(MASTG-(TECH|TOOL|TEST|APP|DEMO)-\d{3,})', replaceReference, markdown)
    updated_markdown = re.sub(r'@(MASWE-\d{3,})', replaceReferenceMASWE, updated_markdown)
    updated_markdown = re.sub(r'@(MASVS-\w+)', replaceReferenceMASVS, updated_markdown)
    tags = page.meta.get('tags', [])
    page.meta["tools"] = list(set(pageRefs["TOOL"]))
    page.meta["techniques"] = list(set(pageRefs["TECH"]))

    return updated_markdown

def getTargetForRef(id, path):
    searchFor = f'./docs/**/{id}.md'

    files = glob(searchFor, recursive=True)

    if not len(files):
        log.error("Unknown reference: " + id)
        return {"file": "ERROR", "title": "error"}
    
    file_url =   os.path.relpath(files[0], "./docs/" + os.path.dirname(path))

    with open(files[0], 'r') as f:
        content = f.read()
        metadata = next(yaml.safe_load_all(content))

        return {"file":file_url, "title":metadata['title']}