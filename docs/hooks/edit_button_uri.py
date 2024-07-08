import logging
log = logging.getLogger('mkdocs')


def on_pre_page(page, config, files):
    try:
        editor_url = config["editor_url"]
    except KeyError:
        return page

    src_path = page.file.src_path
    
    edit_url = f"{editor_url}{src_path}"
    edit_url = edit_url.replace("master/MASTG/", "master/")
    edit_url = edit_url.replace("master/General/", "master/Document/")
    edit_url = edit_url.replace("master/Intro/", "master/Document/")
    edit_url = edit_url.replace("master/iOS/", "master/Document/")
    edit_url = edit_url.replace("master/Android/", "master/Document/")
    edit_url = edit_url.replace("master/MASWE/", "master/weaknesses/")
    
    if edit_url.endswith("/master/index.md") or edit_url.endswith("/master/MASVS/index.md"):
        page.edit_url = ""
    else:
        page.edit_url = edit_url
 
    return page