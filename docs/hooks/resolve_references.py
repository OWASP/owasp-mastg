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

    # Always true, but nice for debugging
    if not path.endswith('/index.md') or True:

        pageRefs = {"TECH":[], "TOOL":[], "TEST": [], "APP": [], "MASWE": [], "MASVS": [], "DEMO": []}
        def replaceReference(match):
            refType = match.group(2)

            pageRefs[refType].append(match.group(1))

            if not match in mapping[refType]:
                target = getTargetForRef(match.group(1), path)
                mapping[refType][match] = target

            icon = ""
            if refType == "TOOL":
                icon = ":material-tools: "
            elif refType == "TEST":
                icon = ":octicons-checklist-24: "
            elif refType == "APP":
                icon = ":fontawesome-solid-mobile-screen-button: "
            elif refType == "DEMO":
                icon = ":material-presentation: "
            else:
                icon = ":material-flask: "

            return f"_[{icon}{mapping[refType][match]['title']}]({mapping[refType][match]['file']})_"

        def replaceReferenceMASWE(match):
            refType = "MASWE"

            pageRefs[refType].append(match.group(1))

            if not match in mapping[refType]:
                target = getTargetForRef(match.group(1), path)
                mapping[refType][match] = target

            icon = ":fontawesome-solid-link-slash: "
            return f"_[{icon}{mapping[refType][match]['title']}]({mapping[refType][match]['file']})_"

        def replaceReferenceMASVS(match):
            refType = "MASVS"

            pageRefs[refType].append(match.group(1))

            if not match in mapping[refType]:
                target = getTargetForRef(match.group(1), path)
                mapping[refType][match] = target

            icon = ":material-book-multiple: "
            return f"_[{icon}{mapping[refType][match]['title']}]({mapping[refType][match]['file']})_"


        updated_markdown = re.sub(r'#(MASTG-(TECH|TOOL|TEST|APP|DEMO)-\d{3,})', replaceReference, markdown)
        updated_markdown = re.sub(r'#(MASWE-\d{3,})', replaceReferenceMASWE, updated_markdown)
        updated_markdown = re.sub(r'#(MASVS-\w{})', replaceReferenceMASVS, updated_markdown)
        tags = page.meta.get('tags', [])
        page.meta["tools"] = list(set(pageRefs["TOOL"]))
        page.meta["techniques"] = list(set(pageRefs["TECH"]))

        return updated_markdown


    return markdown

def getTargetForRef(id, path):
    searchFor = f'./docs/**/{id}.md'

    files = glob(searchFor, recursive=True)

    if not len(files):
        log.error("Unknown reference: " + id)
        return {"file": "ERROR", "title": "error"}
    
    file_url =   os.path.relpath(files[0], "./docs/" + path)[3:]

    with open(files[0], 'r') as f:
        content = f.read()
        metadata = next(yaml.safe_load_all(content))

        return {"file":file_url, "title":metadata['title']}