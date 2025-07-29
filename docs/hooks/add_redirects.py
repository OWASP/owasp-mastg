import os
import mkdocs.plugins
from pathlib import Path

# Lower priority so it runs after the restructure scripts
@mkdocs.plugins.event_priority(-10)
def on_pre_build(config):
    folders = [
        {"base": "docs/MASTG", "subfolders": ["knowledge", "tools", "apps", "techniques", "tests", "rules", "demos", "best-practices"]},
        {"base": "docs/MASWE", "subfolders": [""]},
        {"base": "docs/MASVS", "subfolders": ["controls"]}
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

    # Some hardcoding for MASVS as they have id prefixes
    mapping = {
        "MASVS-STORAGE.md": "05-MASVS-STORAGE.md",
        "MASVS-CRYPTO.md": "06-MASVS-CRYPTO.md",
        "MASVS-AUTH.md": "07-MASVS-AUTH.md",
        "MASVS-NETWORK.md": "08-MASVS-NETWORK.md",
        "MASVS-PLATFORM.md": "09-MASVS-PLATFORM.md",
        "MASVS-CODE.md": "10-MASVS-CODE.md",
        "MASVS-RESILIENCE.md": "11-MASVS-RESILIENCE.md",
        "MASVS-PRIVACY.md": "12-MASVS-PRIVACY.md",
    }
    # loop over mappings and add a redirect for each key-value pair:
    for key, value in mapping.items():
        redirects_dict[key] = f"MASVS/{value}"

    # Ensure the 'redirects' plugin is present
    plugin = config['plugins'].get("redirects")
    if plugin:
        if 'redirect_maps' in plugin.config:
            plugin.config['redirect_maps'].update(redirects_dict)
        elif plugin.name == 'redirects':
            plugin.config['redirect_maps'] = redirects_dict

