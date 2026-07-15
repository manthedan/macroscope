#!/usr/bin/env python3
"""Minimal dependency-free Agent Skills frontmatter validation for CI."""

from pathlib import Path
import re
import sys

skill = Path(__file__).resolve().parents[1] / ".agents/skills/macroscope/SKILL.md"
text = skill.read_text(encoding="utf-8")
parts = text.split("---", 2)
if len(parts) != 3 or parts[0].strip():
    raise SystemExit("SKILL.md must start with YAML frontmatter")

frontmatter = parts[1]
values = {}
for line in frontmatter.splitlines():
    if not line.strip() or line.startswith((" ", "\t")):
        continue
    key, separator, value = line.partition(":")
    if separator:
        values[key.strip()] = value.strip().strip('"\'')

name = values.get("name", "")
description = values.get("description", "")
if not re.fullmatch(r"[a-z0-9]+(?:-[a-z0-9]+)*", name) or len(name) > 64:
    raise SystemExit(f"invalid skill name: {name!r}")
if name != skill.parent.name:
    raise SystemExit("skill name must match its parent directory")
if not description or len(description) > 1024:
    raise SystemExit("skill description must contain 1-1024 characters")

wrapper = skill.parent / "scripts/macroscope-agent"
if not wrapper.is_file() or not wrapper.stat().st_mode & 0o111:
    raise SystemExit("macroscope-agent wrapper is missing or not executable")

print(f"Agent Skill valid: {name}")
