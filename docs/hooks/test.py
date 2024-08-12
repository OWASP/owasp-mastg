import logging
import re
import mkdocs.plugins
import os
from glob import glob
import yaml

log = logging.getLogger('mkdocs')


@mkdocs.plugins.event_priority(50)
def on_page_content(html, page, **kwargs):
    if "Blog" in page.title:
        log.warning("on_page_content")
        log.warning(page)
        log.warning(html)

def on_post_page(output, page, **kwargs):
    if "Blog" in page.title:
        log.warning("on_post_page")
        log.warning(page)
        log.warning(output)