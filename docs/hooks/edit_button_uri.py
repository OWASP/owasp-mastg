import logging
log = logging.getLogger('mkdocs')


def on_pre_page(page, config, files):
    try:
        edit_url_mastg = config["editor_url_mastg"]
        edit_url_masvs = config["editor_url_masvs"]
    except KeyError:
        return page
    
    src_path = page.file.src_path

    # run only if src_path starts with "MASTG", "MASVS", "MASWE", "contributing" or "donate"
    if src_path.startswith(("MASTG", "MASVS", "MASWE", "contributing", "donate")):
    
        edit_url = edit_url_mastg

        # MASVS is in a different repo, so need a different editor url
        if src_path.startswith("MASVS"):
            edit_url = edit_url_masvs
            edit_url = f"{edit_url}{src_path}"

            edit_url = edit_url.replace("master/MASVS/controls", "master/controls/")
            edit_url = edit_url.replace("master/MASVS/", "master/Document/")

        elif src_path.startswith("MASTG") or src_path.startswith("MASWE"):
            edit_url = f"{edit_url}{src_path}"
            # Rewrite some URLs
            edit_url = edit_url.replace("master/MASTG/0x", "master/Document/0x")
            edit_url = edit_url.replace("master/MASTG/", "master/")
            edit_url = edit_url.replace("master/MASWE/", "master/weaknesses/")
        
        elif src_path.startswith("contributing") or src_path.startswith("donate"):
            edit_url = f"{edit_url}{src_path}"
            edit_url = edit_url.replace("master/", "master/docs/")

        # index.md files are mostly auto-generated and an edit link would result in a 404
        # Setting it to empty prevents the button from being added
        if edit_url.endswith("/index.md"):
            page.edit_url = ""
        else:
            page.edit_url = edit_url
    else:
        page.edit_url = ""
 
    return page