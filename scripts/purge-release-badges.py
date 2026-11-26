"""Refresh the two GitHub README version badges after a release."""
import os
import sys
from html.parser import HTMLParser
from urllib.error import URLError
from urllib.request import Request, urlopen


BADGES = {
    "https://img.shields.io/crates/v/estus-mcp": "crates.io",
    "https://img.shields.io/pypi/v/estus": "PyPI",
}


class ReadmeImages(HTMLParser):
    def __init__(self):
        super().__init__()
        self.badges = {}

    def handle_starttag(self, tag, attrs):
        if tag == "img":
            image = dict(attrs)
            origin = image.get("data-canonical-src")
            src = image.get("src", "")
            if origin in BADGES and src.startswith("https://camo.githubusercontent.com/"):
                self.badges[origin] = src


def main():
    images = ReadmeImages()
    repo = os.environ["GITHUB_REPOSITORY"]
    with urlopen(f"https://github.com/{repo}", timeout=20) as page:
        images.feed(page.read().decode())
        images.close()

    for origin, name in BADGES.items():
        if origin not in images.badges:
            print(f"::warning::Could not find the {name} Camo image in the README")
            continue
        try:
            with urlopen(Request(images.badges[origin], method="PURGE"), timeout=20):
                print(f"Purged the {name} version badge")
        except URLError as error:
            print(f"::warning::Could not purge the {name} badge: {error}")


if __name__ == "__main__":
    try:
        main()
    except URLError as error:
        sys.exit(f"Could not fetch the rendered README: {error}")
