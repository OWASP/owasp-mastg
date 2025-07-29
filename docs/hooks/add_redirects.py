import os
import mkdocs.plugins

# Lower priority so it runs after the restructure scripts
@mkdocs.plugins.event_priority(-10)
def on_pre_build(config):
    folders = [
        {"base": "docs/MASTG", "subfolders": ["tools", "apps", "techniques", "tests", "rules", "demos", "best-practices"]},
        {"base": "docs/MASWE", "subfolders": [""]}
    ]

    redirects_dict = {}

    for folder_group in folders:
        base_dir = folder_group["base"]
        for subfolder in folder_group["subfolders"]:
            folder_path = os.path.join(base_dir, subfolder)
            for root, _, files in os.walk(folder_path):
                for file in files:
                    if "index.md" in file.lower() or "readme.md" in file.lower():
                        continue
                    if file.endswith('.md'):
                        relative_path = os.path.relpath(os.path.join(root, file), "docs")
                        redirects_dict[file] = relative_path.replace(os.sep, "/")

    # Ensure the 'redirects' plugin is present
    plugin = config['plugins'].get("redirects")
    if plugin:
        if 'redirect_maps' in plugin.config:
            plugin.config['redirect_maps'].update(redirects_dict)
        elif plugin.name == 'redirects':
            plugin.config['redirect_maps'] = redirects_dict

