import logging
import re
import mkdocs.plugins
import os
from glob import glob
import yaml
log = logging.getLogger('mkdocs')

mapping = {"TECH":{}, "TOOL":{} }

@mkdocs.plugins.event_priority(-50)
def on_page_markdown(markdown, page, **kwargs):
    path = page.file.src_uri

    if path.endswith('file-diff/test.md'):

        pageRefs = {"TECH":[], "TOOL":[] }
        def replaceReference(match):
            refType = match.group(2)

            pageRefs[refType].append(match.group(1))

            if not match in mapping[refType]:
                target = getTargetForRef(match.group(1))
                mapping[refType][match] = target

            icon = ""
            if refType == "TOOL":
                icon = ":material-cog:Tool: "
            else:
                icon = ":material-flask:Technique: "

            return f"_[{icon}{mapping[refType][match]['title']}]({mapping[refType][match]['file']})_"

        updated_markdown = re.sub(r'#(MASTG-(TECH|TOOL)-\d{3,})', replaceReference, markdown)
        tags = page.meta.get('tags', [])
        page.meta["tools"] = list(set(pageRefs["TOOL"]))
        page.meta["techniques"] = list(set(pageRefs["TECH"]))


        return updated_markdown


    return markdown

def getTargetForRef(id):
    searchFor = os.getcwd() + f'/docs/MASTG/**/{id}.md'

    files = glob(searchFor, recursive=True)

    if not len(files):
        log.error("Unknown reference: " + id)
        return {"file": "ERROR", "title": "error"}
    

    with open(files[0], 'r') as f:
        content = f.read()
        metadata = next(yaml.safe_load_all(content))

        return {"file":files[0], "title":metadata['title']}
