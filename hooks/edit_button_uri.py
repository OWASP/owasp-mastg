import logging

log = logging.getLogger('mkdocs')

def get_edit_url(src_path, edit_url_mastg, edit_url_masvs, edit_url_maswe):
    if src_path.startswith("MASVS"):
        edit_url = f"{edit_url_masvs}{src_path}"
        edit_url = edit_url.replace("master/MASVS/controls", "master/controls/")
        edit_url = edit_url.replace("master/MASVS/", "master/Document/")
    elif src_path.startswith("MASTG"):
        edit_url = f"{edit_url_mastg}{src_path}"
        edit_url = edit_url.replace("master/MASTG/0x", "master/Document/0x")
        edit_url = edit_url.replace("master/MASTG/", "master/")

        # TODO Remove after porting v1 is completed
        if 'MASTG-TEST-02' in src_path:
            edit_url = edit_url.replace('/tests/', '/tests-beta/')
    elif src_path.startswith("MASWE"):
        edit_url = f"{edit_url_maswe}{src_path}"
        edit_url = edit_url.replace("main/MASWE/", "main/weaknesses/")
    elif src_path.startswith(("contributing", "donate")):
        edit_url = f"{edit_url_mastg}{src_path}"
        edit_url = edit_url.replace("master/", "master/docs/")
    else:
        edit_url = ""

    return edit_url

def on_pre_page(page, config, files):
    try:
        edit_url_mastg = "https://github.com/OWASP/mastg/edit/master/"
        edit_url_masvs = "https://github.com/OWASP/masvs/edit/master/"
        edit_url_maswe = "https://github.com/OWASP/maswe/edit/main/"
    except KeyError:
        return page

    src_path = page.file.src_path

    if src_path.startswith(("MASTG", "MASVS", "MASWE", "contributing", "donate")):
        edit_url = get_edit_url(src_path, edit_url_mastg, edit_url_masvs, edit_url_maswe)
        if edit_url.endswith("/index.md"):
            page.edit_url = ""
        else:
            page.edit_url = edit_url
    else:
        page.edit_url = ""

    return page