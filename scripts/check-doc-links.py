#!/usr/bin/env python3
"""Check local links in the repository's Markdown documentation."""

import argparse
from bisect import bisect_right
from functools import cache
from html import unescape
from pathlib import Path
import re
import sys
from unicodedata import category
from urllib.parse import unquote, urlsplit


FENCE = re.compile(r"^ {0,3}(?:(`{3,})[^`]*|(~{3,}).*)$")
QUOTE = re.compile(r"^(?: {0,3}>[ \t]?)+")
ATX = re.compile(r"^ {0,3}#{1,6}(?:[ \t]+|$)(.*)$")
SETEXT = re.compile(r"^ {0,3}(?:=+|-+)[ \t]*$")
TICKS = re.compile(r"`+")
INLINE_BLOCK = re.compile(r"(\n[ \t]*\n|^ {0,3}#{1,6}(?:[ \t][^\n]*)?$)", re.MULTILINE)
ESCAPE = re.compile(r"\\([!-/:-@\[-`{-~])")
PUNCTUATION_OR_BRACKET = re.compile(r"\\[!-/:-@\[-`{-~]|[\[\]]")
REFERENCE = re.compile(r"^ {0,3}\[(?:\\.|[^\[\]\\\n])+\]:[ \t]*(?:\n[ \t]*)?", re.MULTILINE)
TITLE = re.compile(r'''\s+(?:"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'|\((?:\\.|[^()\\])*\))''')
ANGLE_DESTINATION = re.compile(r"<((?:\\.|[^<>\\\n])*)>")
LINK_SPACE = re.compile(r"[ \t\n]*")
LINK_CLOSE = re.compile(r"[ \t\n]*\)")
HEADING_LITERAL = re.compile(r"\0(\d+)\0")
HTML_TAG = re.compile(r"</?[A-Za-z][A-Za-z0-9-]*(?:\s+[^<>]*?)?\s*/?>")
HTML_ANCHOR = re.compile(r'''\s(?:name|id)\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))''', re.IGNORECASE)
LINE_ANCHOR = re.compile(r"L([1-9][0-9]*)(?:-L([1-9][0-9]*))?\Z")


def markdown_text(path):
    """Remove fenced code, keeping line numbers for diagnostics."""
    lines = []
    fence = None
    for raw in path.read_text(encoding="utf-8").splitlines():
        quote = QUOTE.match(raw)
        line = raw[quote.end():] if quote else raw
        quote_depth = quote[0].count(">") if quote else 0
        if fence:
            marker, depth = fence
            if quote_depth >= depth:
                closing = line.rstrip(" \t").lstrip(" ")
                if (
                    quote_depth == depth
                    and len(line) - len(line.lstrip(" ")) <= 3
                    and len(closing) >= len(marker)
                    and not closing.strip(marker[0])
                ):
                    fence = None
                lines.append("")
                continue
            fence = None
        if match := FENCE.fullmatch(line):
            fence = match[1] or match[2], quote_depth
            lines.append("")
        else:
            lines.append(line)
    return "\n".join(lines)


def code_spans(text):
    # A span can cross a soft line break, but not a block boundary.
    start = 0
    for block in INLINE_BLOCK.split(text):
        runs = {}
        for match in TICKS.finditer(block):
            runs.setdefault(len(match[0]), []).append(match.start())
        pos = 0
        while match := TICKS.search(block, pos):
            # An odd number of backslashes escapes the opening backtick only.
            opening = match.start()
            while opening and block[opening - 1] == "\\":
                opening -= 1
            opening = match.start() + (match.start() - opening) % 2
            pos = match.end()
            length = pos - opening
            candidates = runs.get(length, ())
            index = bisect_right(candidates, opening)
            if index < len(candidates):
                close = candidates[index]
                code = block[pos:close].replace("\n", " ")
                if code.startswith(" ") and code.endswith(" ") and code.strip(" "):
                    code = code[1:-1]
                pos = close + length
                yield start + opening, start + pos, code
        start += len(block)


def mask_code(text):
    parts = []
    end = 0
    for start, stop, _ in code_spans(text):
        parts.extend((text[end:start], re.sub(r"[^\n]", "\0", text[start:stop])))
        end = stop
    parts.append(text[end:])
    return "".join(parts)


def destination(text, start):
    """Read an angle-delimited or bare Markdown link destination."""
    if text.startswith("<", start):
        match = ANGLE_DESTINATION.match(text, start)
        return (match[1], match.end()) if match else (None, start)

    depth = 0
    end = start
    while end < len(text):
        char = text[end]
        if char.isspace() or char == "\0":
            break
        if ESCAPE.match(text, end):
            end += 2
            continue
        if char == "(":
            depth += 1
        elif char == ")":
            if not depth:
                break
            depth -= 1
        end += 1
    return (None, start) if depth else (text[start:end], end)


def inline_links(text):
    """Yield the opening bracket, closing parenthesis, label and destination."""
    brackets = []
    pos = 0
    while (token := PUNCTUATION_OR_BRACKET.search(text, pos)) is not None:
        pos = token.end()
        if token[0] == "[":
            brackets.append(token.start())
        elif token[0] == "]" and brackets:
            start = brackets.pop()
            if not text.startswith("(", pos):
                continue
            target_start = LINK_SPACE.match(text, pos + 1).end()
            target, end = destination(text, target_start)
            if target is None:
                continue
            title = TITLE.match(text, end)
            close = LINK_CLOSE.match(text, title.end() if title else end)
            if close:
                yield start, close.end(), text[start + 1:token.start()], target
                pos = close.end()


def links(text):
    masked = mask_code(text)
    for match in REFERENCE.finditer(masked):
        # Reference links, including shortcut references, share this destination.
        target, _ = destination(masked, match.end())
        if target:
            yield match.start(), target
    for start, _, _, target in inline_links(masked):
        yield start, target


def heading_text(text):
    # Protect code and escaped punctuation while removing Markdown formatting.
    literals = []

    def literal(value):
        literals.append(value)
        return f"\0{len(literals) - 1}\0"

    pieces = []
    end = 0
    for start, stop, code in code_spans(text):
        pieces.extend((ESCAPE.sub(lambda m: literal(m[1]), text[end:start]), literal(code)))
        end = stop
    pieces.append(ESCAPE.sub(lambda m: literal(m[1]), text[end:]))
    plain = "".join(pieces)
    for start, end, label, _ in reversed(list(inline_links(plain))):
        plain = plain[:start] + label + plain[end:]
    plain = HTML_TAG.sub("", plain)
    plain = re.sub(r"(?<!\w)(_+)(?=\S)(.*?)(?<=\S)\1(?!\w)", r"\2", plain)
    return HEADING_LITERAL.sub(lambda m: literals[int(m[1])], unescape(plain))


def headings(text):
    paragraph = []
    for line in text.splitlines():
        if match := ATX.fullmatch(line):
            yield re.sub(r"(?:^|[ \t]+)#+[ \t]*$", "", match[1]).strip()
            paragraph.clear()
        elif SETEXT.fullmatch(line) and paragraph:
            yield " ".join(paragraph)
            paragraph.clear()
        elif not line.strip() or re.match(r"^ {0,3}(?:[-+*][ \t]|\d+[.)][ \t]|\[.*\]:)", line):
            paragraph.clear()
        else:
            paragraph.append(line.strip())


@cache
def anchors(path):
    text = markdown_text(path)
    seen = set()
    suffixes = {}
    for heading in headings(text):
        word = heading_text(heading).lower().replace(" ", "-")
        slug = "".join(char for char in word if char in "-_" or category(char)[0] in "LMN")
        anchor = slug
        while anchor in seen:
            suffixes[slug] = suffixes.get(slug, 0) + 1
            anchor = f"{slug}-{suffixes[slug]}"
        seen.add(anchor)
    for tag in HTML_TAG.finditer(mask_code(text)):
        for groups in HTML_ANCHOR.findall(tag[0]):
            if value := next((value for value in groups if value), ""):
                seen.add(unescape(value))
    return seen


def has_anchor(path, fragment):
    if path.suffix.lower() == ".md":
        return fragment in anchors(path)
    # GitHub also supports line links to source files.
    if path.is_file() and (match := LINE_ANCHOR.fullmatch(fragment)):
        first = int(match[1])
        last = int(match[2] or match[1])
        with path.open("rb") as lines:
            return first <= last <= sum(1 for _ in lines)
    return False


@cache
def child_names(path):
    return {child.name for child in path.iterdir()} if path.is_dir() else set()


def resolve_local(root, path):
    # Check component spelling even on case-insensitive file systems.
    if not path.is_relative_to(root):
        return None
    current = root
    for part in path.relative_to(root).parts:
        if part == ".." and current != root:
            current = current.parent
        elif part in child_names(current):
            current = (current / part).resolve()
            if not current.is_relative_to(root):
                return None
        else:
            return None
    return current if current.exists() else None


def check(root, path, target):
    try:
        url = urlsplit(unescape(ESCAPE.sub(r"\1", target)))
    except ValueError:
        return "invalid link destination"
    if url.scheme or url.netloc:
        return None
    if url.path.startswith("/"):
        destination_path = root / unquote(url.path.lstrip("/"))
    elif url.path:
        destination_path = path.parent / unquote(url.path)
    else:
        destination_path = path
    destination_path = resolve_local(root, destination_path)
    if destination_path is None:
        return "target does not exist in the repository"
    if url.fragment and not has_anchor(destination_path, unquote(url.fragment)):
        return "anchor does not exist"
    return None


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("root", nargs="?", type=Path, default=Path(__file__).resolve().parents[1])
    root = parser.parse_args().root.resolve()
    pages = [root / name for name in ("README.md", "CONTRIBUTING.md", "SECURITY.md", "examples/README.md")]
    pages.extend((root / "docs").rglob("*.md"))
    failed = False
    for path in sorted(pages):
        text = markdown_text(path)
        line_breaks = [match.start() for match in re.finditer("\n", text)]
        for pos, target in sorted(links(text)):
            if reason := check(root, path, target):
                print(f"{path.relative_to(root)}:{bisect_right(line_breaks, pos) + 1}: {reason}: {target}", file=sys.stderr)
                failed = True
    return int(failed)


if __name__ == "__main__":
    sys.exit(main())
