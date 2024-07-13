import logging
import re
import mkdocs.plugins
import os
from glob import glob
import yaml
log = logging.getLogger('mkdocs')

mapping = {"TECH":{}, "TOOL":{}, "TEST": {}, "APP": {}}

@mkdocs.plugins.event_priority(-50)
def on_page_markdown(markdown, page, **kwargs):
    path = page.file.src_uri

    if not path.endswith('/index.md'):

        pageRefs = {"TECH":[], "TOOL":[], "TEST": [], "APP": []}
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
                icon = ":material-check-bold: "
            elif refType == "APP":
                icon = ":fontawesome-solid-mobile-screen-button: "
            else:
                icon = ":material-flask: "

            return f"_[{icon}{mapping[refType][match]['title']}]({mapping[refType][match]['file']})_"

        updated_markdown = re.sub(r'#(MASTG-(TECH|TOOL|TEST|APP)-\d{3,})', replaceReference, markdown)
        tags = page.meta.get('tags', [])
        page.meta["tools"] = list(set(pageRefs["TOOL"]))
        page.meta["techniques"] = list(set(pageRefs["TECH"]))

        return updated_markdown


    return markdown

def getTargetForRef(id, path):
    searchFor = f'./docs/MASTG/**/{id}.md'

    files = glob(searchFor, recursive=True)

    if not len(files):
        log.error("Unknown reference: " + id)
        return {"file": "ERROR", "title": "error"}
    
    file_url =   os.path.relpath(files[0], "./docs/" + path)[3:]
    # log.error("From: " + path)
    # log.error("Tooo: " + files[0])
    # log.error(file_url)
    # log.error(" ")

    with open(files[0], 'r') as f:
        content = f.read()
        metadata = next(yaml.safe_load_all(content))

        return {"file":file_url, "title":metadata['title']}