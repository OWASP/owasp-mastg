import os
import shutil
import platform
from pathlib import Path
import glob
import logging

log = logging.getLogger('mkdocs')

def on_pre_build(config):
    docs_dir = Path("docs")
    masvs_docs_dir = docs_dir / "MASVS"
    masvs_images_dir = docs_dir / "assets" / "MASVS" / "Images"

    masvs_candidates = [Path("../owasp-masvs"), Path("./owasp-masvs")]
    masvs_dir = next((p for p in masvs_candidates if p.is_dir()), None)

    log.info(f"Using MASVS directory: {masvs_dir}")

    if not masvs_dir:
        raise SystemExit("Error: Please clone owasp-masvs to same directory as owasp-mastg: cd .. && git clone https://github.com/OWASP/owasp-masvs.git")

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
        with open(file_path, "r", encoding="utf-8") as f:
            content = f.read()
        content = content.replace(old, new)
        with open(file_path, "w", encoding="utf-8") as f:
            f.write(content)

    # Replacement patterns
    for md_path in Path(masvs_docs_dir).rglob("*.md"):
        if "controls" in str(md_path):
            replace_in_file(md_path, "images/", "../../../assets/MASVS/Images/")
        else:
            replace_in_file(md_path, "images/", "../../assets/MASVS/Images/")
