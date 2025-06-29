import mkdocs.plugins
import github_api
import json

def get_android_demo_buttons(page, artifacts_url):
    id = page.meta.get('id')

    page_uri = page.file.src_uri

    demo_folder = page_uri.replace("MASTG/demos/android/", "https://github.com/OWASP/owasp-mastg/blob/master/demos/android/").replace(f"/{id}.md", "/")

    banner = f"""
<a href="{artifacts_url}" class="md-button md-button--primary" style="margin: 5px; min-width: 12em;">:material-download:  Download {id} APK</a>
<a href="{demo_folder}" target='_blank' class="md-button md-button--primary" style="margin: 5px; min-width: 12em;">:material-folder-open:  Open {id} Folder</a>
<a href="https://github.com/cpholguera/MASTestApp-Android" target='_blank' class="md-button md-button--primary" style="margin: 5px; min-width: 12em;">:fontawesome-solid-compass-drafting: Build {id} APK</a>
"""
    return banner

def get_ios_demo_buttons(page, artifacts_url):


    id = page.meta.get('id')

    page_uri = page.file.src_uri

    demo_folder = page_uri.replace("MASTG/demos/ios/", "https://github.com/OWASP/owasp-mastg/blob/master/demos/ios/").replace(f"/{id}.md", "/")

    banner = f"""
<a href="{artifacts_url}" class="md-button md-button--primary" style="margin: 5px; min-width: 12em;">:material-download:  Download {id} IPA</a>
<a href="{demo_folder}" target='_blank' class="md-button md-button--primary" style="margin: 5px; min-width: 12em;">:material-folder-open:  Open {id} Folder</a>
<a href="https://github.com/cpholguera/MASTestApp-iOS" target='_blank' class="md-button md-button--primary" style="margin: 5px; min-width: 12em;">:fontawesome-solid-compass-drafting: Build {id} IPA</a>
"""
    return banner


def get_demos_placeholder_banner(meta):
    id = meta.get('id')
    note = meta.get('note', None)
    test = meta.get('test', None)

    banner = f"""
!!! warning "Placeholder MASTG-DEMO"

    This demo hasn't been created yet and it's a **placeholder**. But you can check its status or start working on it yourself.
    If the issue has not yet been assigned, you can request to be assigned to it and submit a PR with the new content for that demo by following our [guidelines](https://docs.google.com/document/d/1EMsVdfrDBAu0gmjWAUEs60q-fWaOmDB5oecY9d9pOlg/edit?pli=1&tab=t.0#heading=h.j1tiymiuocrm).

    <a href="https://github.com/OWASP/owasp-mastg/issues?q=is%3Aopen+{id}" target="_blank">:material-github: Check our GitHub Issues for {id}</a>

    If an issue doesn't exist yet, please create one and assign it to yourself or request to be assigned to it.

## Draft Description

{note}

For more details, check the associated test: @{test}

"""
    return banner

# The snippets get added at -40 so this needs to be earlier
@mkdocs.plugins.event_priority(-30)
def on_page_markdown(markdown, page, config, **kwargs):
    path = page.file.src_uri

    buttons = []

    if "MASTG/demos/android/" in path and not page.meta.get('status') == 'placeholder':
        buttons.append(get_android_demo_buttons(page, config["artifacts_url_android"].get(page.meta.get('id'), config["default_android"])))
    elif "MASTG/demos/ios/" in path and not page.meta.get('status') == 'placeholder':
        buttons.append(get_ios_demo_buttons(page, config["artifacts_url_ios"].get(page.meta.get('id'), config["default_ios"])))
    elif "MASTG/demos/" in path and page.meta.get('status') == 'placeholder':
        buttons.append(get_demos_placeholder_banner(page.meta))

    if buttons:
        markdown = "\n\n".join(buttons) + "\n\n" + markdown

    return markdown

def on_config(config):

    fallback_ios = "https://github.com/OWASP/owasp-mastg/actions/workflows/build-ios-demos.yml"
    fallback_android = "https://github.com/OWASP/owasp-mastg/actions/workflows/build-android-demos.yml"

    config["artifacts_url_ios"], better_fallback_ios = github_api.get_latest_successful_run("build-ios-demos.yml")
    config["artifacts_url_android"], better_fallback_android = github_api.get_latest_successful_run("build-android-demos.yml")

    config["default_ios"] = better_fallback_ios if better_fallback_ios else fallback_ios
    config["default_android"] = better_fallback_android if better_fallback_android else fallback_android
    
    return config