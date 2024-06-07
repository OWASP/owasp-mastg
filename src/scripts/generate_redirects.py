import os


# Base directory
base_dir = "docs/MASTG/"

# Folders to iterate through
folders = ["tools", "apps", "techniques", "tests"]

# Construct the redirect dictionary
redirects_dict = {}
for folder in folders:
    for root, _, files in os.walk(os.path.join(base_dir, folder)):
        for file in files:
            if file.endswith('.md'):
                relative_path = os.path.relpath(os.path.join(root, file), base_dir)
                redirects_dict[f"MASTG/{file}"] = f"MASTG/{relative_path}"

def add_redirects_to_mkdocs(redirects_dict):
    with open("mkdocs.yml", 'r') as f:
        content = f.read()

    # Convert the redirects_dict to a string in the desired format
    redirects_str = "\n".join([f"        {k}: {v}" for k, v in redirects_dict.items()])
    redirects_section = f"  - redirects:\n      redirect_maps:\n{redirects_str}"

    # Check if the plugins section exists
    if 'plugins:' in content:
        # Append the redirects to the plugins section
        content = content.replace('plugins:', f'plugins:\n{redirects_section}', 1)
    else:
        # Or add the plugins section to the end of the file
        content += f"\nplugins:\n{redirects_section}\n"

    with open("mkdocs.yml", 'w') as f:
        f.write(content)

add_redirects_to_mkdocs(redirects_dict)
