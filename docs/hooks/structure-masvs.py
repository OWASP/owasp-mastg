import os
import shutil
import platform
from pathlib import Path
import glob
import logging
import checklist_utils

log = logging.getLogger('mkdocs')

def on_pre_build(config):
    docs_dir = Path("docs")
    masvs_docs_dir = docs_dir / "MASVS"
    masvs_images_dir = docs_dir / "assets" / "MASVS" / "Images"

    masvs_candidates = [Path("../masvs"), Path("./masvs")]
    masvs_dir = next((p for p in masvs_candidates if p.is_dir()), None)

    if not masvs_dir:
        raise Exception("Error: Please clone the masvs to same parent directory as mastg: cd .. && git clone https://github.com/OWASP/masvs.git")

    log.info(f"Using MASVS directory: {masvs_dir}")

    # Clean MASVS dir except Index.md
    if masvs_docs_dir.exists():
        for item in masvs_docs_dir.iterdir():
            if item.name != "index.md":
                if item.is_dir():
                    shutil.rmtree(item)
                else:
                    item.unlink()

    if masvs_images_dir.exists():
        shutil.rmtree(masvs_images_dir)

    masvs_docs_dir.mkdir(parents=True, exist_ok=True)
    masvs_images_dir.mkdir(parents=True, exist_ok=True)

    # Copy all *-*.md files
    for md_file in masvs_dir.glob("Document/*-*.md"):
        shutil.copy(md_file, masvs_docs_dir / md_file.name)

    # Copy controls/
    controls_src = masvs_dir / "controls"
    controls_dest = masvs_docs_dir / "controls"
    if controls_dest.exists():
        shutil.rmtree(controls_dest)
    shutil.copytree(controls_src, controls_dest, dirs_exist_ok=True)

    # Copy images
    for img in (masvs_dir / "Document/images").glob("*"):
        shutil.copy(img, masvs_images_dir / img.name)

    # Determine platform-specific sed workaround (we use pure Python instead)
    def replace_in_file(file_path, old, new):
        path = Path(file_path)
        content = path.read_text(encoding="utf-8").replace(old, new)
        path.write_text(content, encoding="utf-8")

    # Replacement patterns
    for md_path in Path(masvs_docs_dir).rglob("*.md"):
        if "controls" in str(md_path):
            replace_in_file(md_path, "images/", "../../../assets/MASVS/Images/")
        else:
            replace_in_file(md_path, "images/", "../../assets/MASVS/Images/")


    # The controls pages are prettyfied with some styling
    masvs_v2 = checklist_utils.retrieve_masvs()
    MAS_BLUE = "499FFF"

    for group in masvs_v2['groups']:
        for control in group['controls']:
            content = f'# {control["id"]}\n\n'
            content += f'<p style="font-size: 2em">{control["statement"]}</p>\n\n'
            # add html thick separation line in blue 
            content += f'<hr style="height: 0.2em; background-color: #{MAS_BLUE}; border: 0;" />\n\n'
            content += f'{control["description"]}\n'

            with open(os.path.join('docs/MASVS/controls', f'{control["id"]}.md'), 'w') as f:
                f.write(content)
