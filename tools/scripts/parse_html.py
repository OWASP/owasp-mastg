#!/usr/bin/python

from bs4 import BeautifulSoup
import re
import yaml
from dataclasses import dataclass, asdict
from pathlib import Path

# docker run --rm -u `id -u`:`id -g` -v `pwd`:/pandoc dalibo/pandocker --section-divs 0x05g-Testing-Network-Communication.md -o 0x05g-Testing-Network-Communication.html

# https://python-markdown.github.io/extensions/fenced_code_blocks/
# http://zetcode.com/python/beautifulsoup/

MASVS_TITLES = {
    "V1": "Architecture, Design and Threat Modeling Requirements",
    "V2": "Data Storage and Privacy Requirements",
    "V3": "Cryptography Requirements",
    "V4": "Authentication and Session Management Requirements",
    "V5": "Network Communication Requirements",
    "V6": "Platform Interaction Requirements",
    "V7": "Code Quality and Build Setting Requirements",
    "V8": "Resilience Requirements",
}


@dataclass
class TestCase:
    mstg_id: str
    link: str
    title: str
    platform: str
    mstg_ids: list
    tools: list
    overview: str


def get_testcases_info(chapter_file_name, chapter):
    testcases = chapter.find_all(["section"], {"class": "level2"})
    testcases_info = []

    for testcase in testcases:
        title = testcase.find("h2").get_text()
        mstg_id = testcase.get("id")
        link = f"https://github.com/OWASP/owasp-mstg/blob/master/Document/{chapter_file_name}#{mstg_id}"
        platform = "android" if chapter_file_name.startswith("0x05") else "ios"
        mstg_ids = re.findall(r"MSTG-\w+-\d+", title)
        tools = get_all_links_to_tools(testcase)
        overview = get_section_plain_text(testcase, "overview")
        # static = get_section_plain_text(testcase, 'static')
        # dynamic = get_section_plain_text(testcase, 'dynamic')

        testcases_info.append(
            TestCase(mstg_id, link, title, platform, mstg_ids, tools, overview)
        )

    testcases_info = [asdict(tc) for tc in testcases_info]
    return testcases_info


def print_yaml(data_dict):
    print(yaml.dump(data_dict, allow_unicode=True, indent=4, default_flow_style=False, sort_keys=False))


def write_yaml_file(name, data_dict):
    Path(name).write_text(yaml.dump(data_dict, allow_unicode=True, indent=4, default_flow_style=False, sort_keys=False))


def get_section_plain_text(chapter, starts_with_str):

    sections = chapter.find_all(["section"], {"class": "level3", "id": re.compile(f"{starts_with_str}-?.*")})
    if sections:
        return sections[0].get_text()
    else:
        return ""


def get_sections_plain_text(chapter, starts_with_str):

    testcase_sections = chapter.find_all(["section"], {"class": "level3", "id": re.compile(f"{starts_with_str}-?.*")})

    for section in testcase_sections:
        print(section.get_text())


def get_sections_innerHtml(chapter, starts_with_str, remove_title=False):
    testcase_sections = chapter.find_all(["section"], {"class": "level3", "id": re.compile(f"{starts_with_str}-?.*")})

    for section in testcase_sections:
        if remove_title:
            section.contents = section.contents[2:]
        print(section.encode_contents())


def get_links_to_other_chapters(chapter):
    links = chapter.find_all(["a"], {"href": re.compile(r"0x0.*\.md#.*")})
    return [link.get("href") for link in links]


def get_all_links_to_tools(chapter):
    links = chapter.find_all(["a"], {"href": re.compile(r"0x08.*\.md#.*")})
    return [link.get("href") for link in links]


def get_links_to_tools_per_section(chapter):
    sections_level2 = chapter.find_all(["section"], {"class": "level2"})
    tool_links = {}
    for section in sections_level2:
        found_links = get_all_links_to_tools(section)
        tool_links[section.get("id")] = found_links

    return tool_links


def write_file(masvs_file, input_file, output_file):
    """
    Parses the MASTG and completes the MASVS file with information from the MASTG.
    """

    # enhanced_masvs_dict = {}
    # for file in Path('masvs_yaml').glob('*.yaml'):
    #     masvs_dict = yaml.load(open(file))
    #     enhanced_masvs_dict[MASVS_TITLES[file.stem]] = masvs_dict

    masvs = yaml.safe_load(open(masvs_file))

    testcases_info = []

    for file in Path(input_file).glob("*.html"):

        contents = file.read_text()

        chapter = BeautifulSoup(contents, "lxml")

        # print(get_links_to_other_chapters(chapter))

        # print(get_all_links_to_tools(chapter))
        # print(get_links_to_tools_per_section(chapter))

        testcases_info += get_testcases_info(f"{file.stem}.md", chapter)
        # print_yaml(testcases_info)

        # print(get_sections_plain_text(chapter, "overview"))
        # print(get_sections_innerHtml(chapter, "overview"))

    for tc in testcases_info:
        for id in tc["mstg_ids"]:
            if masvs.get(id):
                # masvs[id].update(tc)
                masvs_req = masvs[id]
                if not masvs_req.get("links"):
                    masvs_req["links"] = []
                masvs_req["links"].append(tc["link"])
            # masvs_dict[id]['solution'].append(tc['overview']) # todo

    # print_yaml(masvs)
    write_yaml_file(output_file, masvs)


def main():
    import argparse

    parser = argparse.ArgumentParser(description="Export the MASVS requirements as Excel. Default language is en.")
    parser.add_argument("-m", "--masvs", required=True, default="masvs_en.yaml")
    parser.add_argument("-i", "--inputfile", required=True, default="html")
    parser.add_argument("-o", "--outputfile", required=True, default="masvs_full_en.yaml")

    args = parser.parse_args()

    write_file(args.masvs, args.inputfile, args.outputfile)


if __name__ == "__main__":
    main()
