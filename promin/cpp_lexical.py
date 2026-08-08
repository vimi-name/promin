"""Offset-preserving lexical masking for bounded C-family source analysis.

The module deliberately does not claim to parse C or C++.  It removes regions
that cannot safely contribute structural dependency evidence and labels
remaining ambiguity for a caller to report as REVIEW or UNAVAILABLE.
"""

from __future__ import annotations

from dataclasses import dataclass
import re
from typing import Any, Iterable, Mapping, Sequence


class LexicalError(ValueError):
    """Raised only for invalid API input, never converted into a synthetic pass."""


@dataclass(frozen=True)
class MaskedSpan:
    start: int
    end: int
    kind: str


@dataclass(frozen=True)
class MaskedSource:
    source: str
    masked: str
    spans: tuple[MaskedSpan, ...]
    complete: bool
    errors: tuple[str, ...]


@dataclass(frozen=True)
class IdentifierOccurrence:
    name: str
    start: int
    end: int
    exclusion: str | None


_IDENTIFIER = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
_RAW_START = re.compile(r'(?:u8|u|U|L)?R"([^\s\\()]{0,16})\(')
_ORDINARY_START = re.compile(r'(?:u8|u|U|L)?"')
_CHARACTER_START = re.compile(r"(?:u8|u|U|L)?'")
_TEMPLATE_PARAMETER = re.compile(r"\b(?:typename|class)\s+([A-Za-z_][A-Za-z0-9_]*)")
_LOCAL_DECLARATION = re.compile(
    r"\b[A-Za-z_][A-Za-z0-9_]*(?:\s*::\s*[A-Za-z_][A-Za-z0-9_]*)?\s+"
    r"([A-Za-z_][A-Za-z0-9_]*)\s*(?=[=;,\)])"
)


def _line_start(text: str, index: int) -> bool:
    previous = text.rfind("\n", 0, index)
    return all(character in " \t\r" for character in text[previous + 1 : index])


def _quoted_end(text: str, quote_index: int, quote: str) -> int | None:
    index = quote_index + 1
    while index < len(text):
        character = text[index]
        if character == "\\":
            index += 2
            continue
        if character == quote:
            return index + 1
        if character in "\r\n":
            return None
        index += 1
    return None


def _preprocessor_end(text: str, start: int) -> int:
    """Return the end of one logical preprocessor directive, including newlines."""

    index = start
    while index < len(text):
        newline = text.find("\n", index)
        if newline < 0:
            return len(text)
        physical = text[index:newline].rstrip("\r")
        index = newline + 1
        if not physical.endswith("\\"):
            return index
    return len(text)


def _mask_characters(characters: list[str], start: int, end: int) -> None:
    for index in range(start, end):
        if characters[index] not in "\r\n":
            characters[index] = " "


def _valid_embedded_range(value: Any, source_length: int) -> tuple[int, int, str] | None:
    if isinstance(value, Mapping):
        start = value.get("start")
        end = value.get("end")
        kind = value.get("kind", "embedded-language-payload")
    elif isinstance(value, tuple) and len(value) in {2, 3}:
        start, end = value[0], value[1]
        kind = value[2] if len(value) == 3 else "embedded-language-payload"
    else:
        return None
    if (
        not isinstance(start, int)
        or isinstance(start, bool)
        or not isinstance(end, int)
        or isinstance(end, bool)
        or not isinstance(kind, str)
        or not kind
        or start < 0
        or end < start
        or end > source_length
    ):
        return None
    return start, end, kind


def mask_c_family_source(
    source: str,
    *,
    embedded_ranges: Sequence[Mapping[str, Any] | tuple[int, int] | tuple[int, int, str]] = (),
) -> MaskedSource:
    """Mask non-code regions while preserving every character and line offset.

    The returned ``masked`` string has exactly the same length as ``source``;
    CR/LF characters are preserved as-is.  Unterminated literals and malformed
    caller-provided embedded spans set ``complete`` false so callers cannot use
    the result as a structural pass.
    """

    if not isinstance(source, str):
        raise LexicalError("C-family source must be text")
    characters = list(source)
    spans: list[MaskedSpan] = []
    errors: list[str] = []
    index = 0
    complete = True
    while index < len(source):
        if source.startswith("//", index):
            end = source.find("\n", index)
            end = len(source) if end < 0 else end
            _mask_characters(characters, index, end)
            spans.append(MaskedSpan(index, end, "comments"))
            index = end
            continue
        if source.startswith("/*", index):
            close = source.find("*/", index + 2)
            if close < 0:
                end = len(source)
                complete = False
                errors.append("unterminated block comment")
            else:
                end = close + 2
            _mask_characters(characters, index, end)
            spans.append(MaskedSpan(index, end, "comments"))
            index = end
            continue
        if source[index] == "#" and _line_start(source, index):
            end = _preprocessor_end(source, index)
            _mask_characters(characters, index, end)
            spans.append(MaskedSpan(index, end, "preprocessor"))
            index = end
            continue
        raw = _RAW_START.match(source, index)
        if raw is not None:
            delimiter = raw.group(1)
            marker = ")" + delimiter + '"'
            close = source.find(marker, raw.end())
            if close < 0:
                end = len(source)
                complete = False
                errors.append("unterminated raw string")
            else:
                end = close + len(marker)
            _mask_characters(characters, index, end)
            spans.append(MaskedSpan(index, end, "raw-strings"))
            index = end
            continue
        ordinary = _ORDINARY_START.match(source, index)
        if ordinary is not None:
            quote_index = ordinary.end() - 1
            end = _quoted_end(source, quote_index, '"')
            if end is None:
                end = len(source)
                complete = False
                errors.append("unterminated ordinary string")
            _mask_characters(characters, index, end)
            spans.append(MaskedSpan(index, end, "ordinary-strings"))
            index = end
            continue
        character = _CHARACTER_START.match(source, index)
        if character is not None:
            quote_index = character.end() - 1
            end = _quoted_end(source, quote_index, "'")
            if end is None:
                end = len(source)
                complete = False
                errors.append("unterminated character literal")
            _mask_characters(characters, index, end)
            spans.append(MaskedSpan(index, end, "character-literals"))
            index = end
            continue
        index += 1

    for raw_range in embedded_ranges:
        parsed = _valid_embedded_range(raw_range, len(source))
        if parsed is None:
            complete = False
            errors.append("invalid embedded language range")
            continue
        start, end, kind = parsed
        _mask_characters(characters, start, end)
        spans.append(MaskedSpan(start, end, kind))

    masked = "".join(characters)
    if len(masked) != len(source) or masked.count("\n") != source.count("\n") or masked.count("\r") != source.count("\r"):
        raise LexicalError("offset-preserving lexical mask invariant failed")
    return MaskedSource(
        source=source,
        masked=masked,
        spans=tuple(sorted(spans, key=lambda item: (item.start, item.end, item.kind))),
        complete=complete,
        errors=tuple(errors),
    )


def _matching_angle_end(text: str, start: int) -> int | None:
    depth = 0
    for index in range(start, len(text)):
        if text[index] == "<":
            depth += 1
        elif text[index] == ">":
            depth -= 1
            if depth == 0:
                return index + 1
    return None


def _template_parameter_positions(masked: str) -> set[int]:
    starts: set[int] = set()
    for marker in re.finditer(r"\btemplate\s*<", masked):
        end = _matching_angle_end(masked, marker.end() - 1)
        if end is None:
            continue
        for match in _TEMPLATE_PARAMETER.finditer(masked, marker.end(), end):
            starts.add(match.start(1))
    return starts


def _brace_depth_at(text: str, position: int) -> int:
    depth = 0
    for character in text[:position]:
        if character == "{":
            depth += 1
        elif character == "}":
            depth = max(0, depth - 1)
    return depth


def _local_declaration_names(masked: str) -> set[str]:
    names: set[str] = set()
    for match in _LOCAL_DECLARATION.finditer(masked):
        if _brace_depth_at(masked, match.start(1)) > 0:
            names.add(match.group(1))
    return names


def _adjacent_nonspace(text: str, start: int, end: int) -> tuple[str, str]:
    left = start - 1
    while left >= 0 and text[left].isspace():
        left -= 1
    right = end
    while right < len(text) and text[right].isspace():
        right += 1
    return (text[max(0, left - 1) : left + 1], text[right : right + 2])


def c_family_identifiers(
    source: str,
    *,
    embedded_ranges: Sequence[Mapping[str, Any] | tuple[int, int] | tuple[int, int, str]] = (),
) -> tuple[IdentifierOccurrence, ...]:
    """Return identifiers and typed exclusions from the offset-preserving mask.

    The result is intentionally conservative: qualified names are excluded as a
    whole instead of guessing which component owns a dependency, and local
    declaration names remain excluded for the bounded source unit.
    """

    masked_source = mask_c_family_source(source, embedded_ranges=embedded_ranges)
    template_positions = _template_parameter_positions(masked_source.masked)
    local_names = _local_declaration_names(masked_source.masked)
    values: list[IdentifierOccurrence] = []
    for match in _IDENTIFIER.finditer(masked_source.masked):
        name = match.group(0)
        before, after = _adjacent_nonspace(masked_source.masked, match.start(), match.end())
        exclusion: str | None = None
        if match.start() in template_positions:
            exclusion = "template-parameter"
        elif before.endswith(".") or before == "->":
            exclusion = "member-access"
        elif before.endswith("::") or after.startswith("::"):
            exclusion = "qualified-namespace-component"
        elif name in local_names:
            exclusion = "local-declaration"
        values.append(IdentifierOccurrence(name, match.start(), match.end(), exclusion))
    return tuple(values)
