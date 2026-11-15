"""Source locations for the hook fields that need precise diagnostics."""

from __future__ import annotations

import json
import re
from collections.abc import Iterator


class LocatedMapping(dict):
    once_line: int | None = None


# Consume quoted strings whole, including escapes, so braces and keys in values are ignored.
_JSON_TOKENS = re.compile(r'"(?:[^"\\]++|\\.)*+"(?:[ \t\r\n]*:)?|[{}]')


def _json_once_lines(text: str) -> Iterator[int | None]:
    """Yield the last 'once' key's line for each object in closing-brace order."""
    stack: list[int | None] = []
    previous = 0
    line = 1
    for token in _JSON_TOKENS.finditer(text):
        value = token[0]
        if value == "{":
            stack.append(None)
        elif value == "}":
            yield stack.pop()
        elif value.endswith(":") and stack:
            key = value[:-1].rstrip()
            if key == '"once"' or ("\\" in key and json.loads(key) == "once"):
                line += text.count("\n", previous, token.start())
                previous = token.start()
                stack[-1] = line


def load_located_json(text: str):
    locations = _json_once_lines(text)

    def make_mapping(pairs):
        # The decoder calls the hook after parsing each object's children.
        mapping = LocatedMapping(pairs)
        mapping.once_line = next(locations)
        return mapping

    return json.loads(text, object_pairs_hook=make_mapping)
