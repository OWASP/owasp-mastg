import os

def on_config(config):
    base_dir = "docs/MASTG/"
    folders = ["tools", "apps", "techniques", "tests"]

    redirects_dict = {}
    for folder in folders:
        for root, _, files in os.walk(os.path.join(base_dir, folder)):
            for file in files:
                if file.endswith('.md'):
                    relative_path = os.path.relpath(os.path.join(root, file), base_dir)
                    redirects_dict[f"MASTG/{file}"] = f"MASTG/{relative_path}"

    # Ensure the 'redirects' plugin is present
    plugin = config['plugins'].get("redirects")
    if plugin:
        if 'redirect_maps' in plugin.config:
            plugin.config['redirect_maps'].update(redirects_dict)
        elif plugin.name == 'redirects':
            plugin.config['redirect_maps'] = redirects_dict

    return config
