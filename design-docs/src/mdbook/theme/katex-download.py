#!/usr/bin/env python3
# Python 3.5 or above required.
import re
from pathlib import Path

import requests

THEME_PATH = ""
CDN_ROOT = "https://cdn.jsdelivr.net/npm/katex@0.16.9/dist/"
KATEX_CSS_PATH = "katex.min.css"


def write_file_bytes(filename, bytes):
    # Create parent directories.
    path = Path(filename)
    path.parent.mkdir(parents=True, exist_ok=True)

    with open(path, "wb") as file:
        file.write(bytes)


def download_bytes(url):
    request = requests.get(url)
    if request.status_code != 200:
        raise Exception("Failed to download from " + url)
    css_bytes = request.content
    return css_bytes


def font_urls_in_css(css):
    return re.findall(r"url\((fonts\/[^()]+)\)", css)


def download_save(url_base, path, path_base):
    url = url_base + path
    file_path = path_base + path
    print("Downloading from " + url + " to " + file_path)
    file_bytes = download_bytes(url)
    write_file_bytes(file_path, file_bytes)
    return file_bytes


def main():
    css_bytes = download_save(CDN_ROOT, KATEX_CSS_PATH, "")
    # Get URLs to fonts `katex.min.css` relies on.
    css_str = css_bytes.decode(encoding="utf-8")
    font_urls = font_urls_in_css(css_str)
    # Download fonts.
    for url in font_urls:
        download_save(CDN_ROOT, url, THEME_PATH)


if __name__ == "__main__":
    main()