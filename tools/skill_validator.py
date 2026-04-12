#!/usr/bin/env python3
from __future__ import annotations

import argparse
import re
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Sequence, Tuple


REPO_ROOT = Path(__file__).resolve().parents[1]
PRD_DIR = REPO_ROOT / "prd_project_mishka"
SKILLS_DIR = REPO_ROOT / "skills"
NUMERIC_HEADING_RE = re.compile(r"^(#{1,6}) (\d+(?:\.\d+)*)\b.*$")
SYMBOLIC_HEADING_RE = re.compile(r"^(#{1,6}) §(?:([0-9A-Za-z]+)\b.*| .*)$")
SYMBOLIC_SECTION_RE = re.compile(r"^(#{1,6}) §")
MARKER_RE = re.compile(r"^PRD-\d{2} §")


@dataclass(frozen=True)
class SectionRef:
    prd_path: Path
    section_id: str


@dataclass(frozen=True)
class Section:
    label: str
    depth: int
    start: int
    end: int
    symbolic: bool


SKILL_PROJECTIONS: Dict[Path, Tuple[SectionRef, ...]] = {
    (SKILLS_DIR / "architecture_skill.md").resolve(): tuple(
        SectionRef(PRD_DIR / "MISHKA-PRD-01 — System Laws & Invariants.md", section_id)
        for section_id in ("1", "2", "3", "4", "5", "6", "7", "8")
    ),
    (SKILLS_DIR / "compliance_skill.md").resolve(): tuple(
        SectionRef(PRD_DIR / "MISHKA-PRD-19 — Build, Supply Chain & Compliance.md", section_id)
        for section_id in (
            "1",
            "2",
            "3",
            "4",
            "5",
            "6",
            "7",
            "8",
            "9",
            "10",
            "11",
            "12",
            "13",
            "14",
            "15",
            "16",
            "17",
        )
    ),
    (SKILLS_DIR / "cryptography_skill.md").resolve(): tuple(
        SectionRef(PRD_DIR / "MISHKA-PRD-04 — Cryptographic Trust & Key Lifecycle.md", section_id)
        for section_id in ("1", "2", "3", "5", "6", "7", "8", "9", "10", "11", "12", "13")
    ),
}


def build_section_index(text: str) -> Dict[str, Section]:
    lines = text.splitlines(keepends=True)
    headings = []
    offset = 0

    for line in lines:
        numeric_match = NUMERIC_HEADING_RE.match(line.rstrip("\n"))
        symbolic_match = SYMBOLIC_HEADING_RE.match(line.rstrip("\n"))
        if numeric_match:
            label = numeric_match.group(2)
            depth = len(numeric_match.group(1)) - 1
            headings.append((label, depth, offset, False))
        elif symbolic_match:
            label = symbolic_match.group(2) or ""
            depth = len(symbolic_match.group(1)) - 1
            headings.append((label, depth, offset, True))
        offset += len(line)

    sections: Dict[str, Section] = {}
    for index, (label, depth, start, symbolic) in enumerate(headings):
        end = len(text)
        for _next_label, next_depth, next_start, _next_symbolic in headings[index + 1 :]:
            if next_depth <= depth:
                end = next_start
                break
        sections[label] = Section(
            label=label,
            depth=depth,
            start=start,
            end=end,
            symbolic=symbolic,
        )
    return sections


def extract_numeric_clause(text: str, section_id: str, sections: Dict[str, Section]) -> str:
    section = sections.get(section_id)
    if section is None:
        raise ValueError(f"Missing section {section_id}")

    lines = text.splitlines(keepends=True)
    headings: List[Section] = []
    offset = 0
    for line in lines:
        numeric_match = NUMERIC_HEADING_RE.match(line.rstrip("\n"))
        symbolic_match = SYMBOLIC_HEADING_RE.match(line.rstrip("\n"))
        if numeric_match:
            label = numeric_match.group(2)
            depth = len(numeric_match.group(1)) - 1
            headings.append(
                Section(
                    label=label,
                    depth=depth,
                    start=offset,
                    end=len(text),
                    symbolic=False,
                )
            )
        elif symbolic_match:
            label = symbolic_match.group(2) or ""
            depth = len(symbolic_match.group(1)) - 1
            headings.append(
                Section(
                    label=label,
                    depth=depth,
                    start=offset,
                    end=len(text),
                    symbolic=True,
                )
            )
        offset += len(line)

    for index, heading in enumerate(headings):
        end = len(text)
        for next_heading in headings[index + 1 :]:
            if next_heading.depth <= heading.depth:
                end = next_heading.start
                break
        headings[index] = Section(
            label=heading.label,
            depth=heading.depth,
            start=heading.start,
            end=end,
            symbolic=heading.symbolic,
        )

    excluded_ranges: List[Tuple[int, int]] = []
    for heading in headings:
        if heading.start <= section.start or heading.start >= section.end:
            continue
        if heading.depth <= section.depth:
            continue
        if heading.symbolic:
            excluded_ranges.append((heading.start, heading.end))

    if not excluded_ranges:
        return text[section.start : section.end]

    parts: List[str] = []
    cursor = section.start
    for start, end in excluded_ranges:
        if cursor < start:
            parts.append(text[cursor:start])
        cursor = max(cursor, end)
    if cursor < section.end:
        parts.append(text[cursor : section.end])
    return "".join(parts)


def default_paths() -> List[Path]:
    return sorted(path.resolve() for path in SKILLS_DIR.glob("*.md"))


def build_expected_output(
    section_refs: Sequence[SectionRef],
    prd_cache: Dict[Path, str],
    section_cache: Dict[Path, Dict[str, Section]],
) -> str:
    expected_parts: List[str] = []

    for ref in section_refs:
        prd_text = prd_cache.setdefault(ref.prd_path, ref.prd_path.read_text(encoding="utf-8"))
        sections = section_cache.setdefault(ref.prd_path, build_section_index(prd_text))
        if ref.section_id not in sections:
            raise ValueError(f"Missing section {ref.section_id} in {ref.prd_path.name}")
        expected_parts.append(extract_numeric_clause(prd_text, ref.section_id, sections))

    return "".join(expected_parts)


def first_difference(actual: str, expected: str) -> Tuple[int, int]:
    limit = min(len(actual), len(expected))
    for index in range(limit):
        if actual[index] != expected[index]:
            line = actual.count("\n", 0, index) + 1
            line_start = actual.rfind("\n", 0, index)
            column = index + 1 if line_start == -1 else index - line_start
            return line, column

    index = limit
    line = actual.count("\n", 0, index) + 1
    line_start = actual.rfind("\n", 0, index)
    column = index + 1 if line_start == -1 else index - line_start + 1
    return line, column


def ordering_mismatch(actual: str, expected: str) -> bool:
    actual_lines = actual.splitlines(keepends=True)
    expected_lines = expected.splitlines(keepends=True)
    return Counter(actual_lines) == Counter(expected_lines) and actual_lines != expected_lines


def whitespace_mismatch(actual: str, expected: str) -> bool:
    actual_no_ws = "".join(actual.split())
    expected_no_ws = "".join(expected.split())
    return actual_no_ws == expected_no_ws and actual != expected


def unknown_lines(actual: str, source_line_space: Sequence[str]) -> List[int]:
    line_space = set(source_line_space)
    line_numbers: List[int] = []
    for line_number, line in enumerate(actual.splitlines(), start=1):
        if line and line not in line_space:
            line_numbers.append(line_number)
    return line_numbers


def validate_skill(
    path: Path,
    fix: bool,
    prd_cache: Dict[Path, str],
    section_cache: Dict[Path, Dict[str, Section]],
) -> List[str]:
    projection = SKILL_PROJECTIONS.get(path.resolve())
    if projection is None:
        return ["PROJECTION_SPEC_MISSING"]

    expected = build_expected_output(projection, prd_cache, section_cache)
    actual = path.read_text(encoding="utf-8")

    if fix and actual != expected:
        path.write_text(expected, encoding="utf-8")
        actual = expected

    if actual == expected:
        return []

    violations = ["PROJECTION_DRIFT"]

    if any(MARKER_RE.match(line) for line in actual.splitlines()):
        violations.append("NON_PRD_MARKER_PRESENT")

    symbolic_lines = [
        line_number
        for line_number, line in enumerate(actual.splitlines(), start=1)
        if SYMBOLIC_SECTION_RE.match(line)
    ]
    if symbolic_lines:
        violations.append(
            "SYMBOLIC_SECTION_PRESENT lines=" + ",".join(str(line_number) for line_number in symbolic_lines)
        )

    source_line_space: List[str] = []
    for ref in projection:
        prd_text = prd_cache.setdefault(ref.prd_path, ref.prd_path.read_text(encoding="utf-8"))
        source_line_space.extend(prd_text.splitlines())

    missing_lines = unknown_lines(actual, source_line_space)
    if missing_lines:
        violations.append(
            "NON_PRD_CONTENT lines=" + ",".join(str(line_number) for line_number in missing_lines[:10])
        )

    if ordering_mismatch(actual, expected):
        violations.append("ORDERING_MISMATCH")

    if whitespace_mismatch(actual, expected):
        violations.append("WHITESPACE_MISMATCH")

    diff_line, diff_column = first_difference(actual, expected)
    violations.append(f"BYTE_MISMATCH line={diff_line} column={diff_column}")
    return violations


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--fix", action="store_true")
    parser.add_argument("paths", nargs="*")
    args = parser.parse_args()

    prd_cache: Dict[Path, str] = {}
    section_cache: Dict[Path, Dict[str, Section]] = {}
    paths = [Path(path).resolve() for path in (args.paths or [str(path) for path in default_paths()])]

    all_violations: Dict[Path, List[str]] = {}
    for path in paths:
        all_violations[path] = validate_skill(path, args.fix, prd_cache, section_cache)

    if all(not violations for violations in all_violations.values()):
        print("STATUS: PASS")
        print("NO EXTRA CONTENT")
        print("BYTE MATCH VERIFIED")
        return 0

    print("STATUS: FAIL")
    for path, violations in all_violations.items():
        if not violations:
            continue
        print(path)
        for violation in violations:
            print(violation)

    return 1


if __name__ == "__main__":
    raise SystemExit(main())
