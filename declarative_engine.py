#!/usr/bin/env python3
"""Safe local evaluator for a documented subset of Sigma-style detections."""

from __future__ import annotations

import fnmatch
import json
import re
from dataclasses import dataclass
from typing import Any


SUPPORTED_MODIFIERS = {"contains", "startswith", "endswith", "exists", "all", "windash"}


def field_value(event: dict[str, Any], name: str) -> Any:
    """Case-insensitive lookup supporting dotted nested fields."""
    current: Any = event
    for part in name.split("."):
        if not isinstance(current, dict):
            return None
        key = next((item for item in current if item.lower() == part.lower()), None)
        if key is None:
            return None
        current = current[key]
    return current


def scalar_match(actual: Any, expected: Any, modifiers: list[str]) -> bool:
    if "exists" in modifiers:
        return (actual is not None) == bool(expected)
    if actual is None:
        return expected is None
    values = actual if isinstance(actual, list) else [actual]
    expected_values = expected if isinstance(expected, list) else [expected]

    def one(left: Any, right: Any) -> bool:
        if isinstance(left, bool) or isinstance(right, bool) or isinstance(left, (int, float)) and isinstance(right, (int, float)):
            return left == right
        a, b = str(left).lower(), str(right).lower()
        if "windash" in modifiers:
            a, b = a.replace("/", "-"), b.replace("/", "-")
        if "contains" in modifiers: return b in a
        if "startswith" in modifiers: return a.startswith(b)
        if "endswith" in modifiers: return a.endswith(b)
        if "*" in b or "?" in b: return fnmatch.fnmatch(a, b)
        return a == b

    matches = [one(left, right) for left in values for right in expected_values]
    return all(matches) if "all" in modifiers else any(matches)


def selection_match(selection: Any, event: dict[str, Any]) -> bool:
    if isinstance(selection, list):
        if all(isinstance(item, dict) for item in selection):
            return any(selection_match(item, event) for item in selection)
        haystack = json.dumps(event, ensure_ascii=False).lower()
        return any(str(item).lower() in haystack for item in selection)
    if not isinstance(selection, dict):
        return str(selection).lower() in json.dumps(event, ensure_ascii=False).lower()
    for expression, expected in selection.items():
        parts = str(expression).split("|")
        field, modifiers = parts[0], [item.lower() for item in parts[1:]]
        if any(item not in SUPPORTED_MODIFIERS for item in modifiers):
            return False
        if not scalar_match(field_value(event, field), expected, modifiers):
            return False
    return True


def expand_quantifiers(condition: str, names: list[str]) -> str:
    pattern = re.compile(r"\b(1|all)\s+of\s+(them|[A-Za-z0-9_]+\*)(?=\s|$|\))", re.IGNORECASE)
    while True:
        match = pattern.search(condition)
        if not match: break
        chosen = names if match.group(2).lower() == "them" else [name for name in names if fnmatch.fnmatch(name, match.group(2))]
        if not chosen: raise ValueError(f"Condition pattern matched no selections: {match.group(2)}")
        operator = " and " if match.group(1).lower() == "all" else " or "
        condition = condition[:match.start()] + "(" + operator.join(chosen) + ")" + condition[match.end():]
    return condition


class BooleanParser:
    def __init__(self, text: str, values: dict[str, bool]) -> None:
        self.tokens = re.findall(r"\(|\)|\bnot\b|\band\b|\bor\b|[A-Za-z0-9_]+", text, flags=re.IGNORECASE)
        compact = re.sub(r"\s+", "", text)
        if "".join(self.tokens).lower() != compact.lower():
            raise ValueError("Unsupported condition syntax")
        self.values, self.index = values, 0

    def take(self, value: str | None = None) -> str:
        if self.index >= len(self.tokens): raise ValueError("Unexpected end of condition")
        token = self.tokens[self.index]
        if value and token.lower() != value: raise ValueError(f"Expected {value}")
        self.index += 1
        return token

    def expression(self) -> bool:
        result = self.term()
        while self.index < len(self.tokens) and self.tokens[self.index].lower() == "or":
            self.take("or"); right = self.term(); result = result or right
        return result

    def term(self) -> bool:
        result = self.factor()
        while self.index < len(self.tokens) and self.tokens[self.index].lower() == "and":
            self.take("and"); right = self.factor(); result = result and right
        return result

    def factor(self) -> bool:
        if self.tokens[self.index].lower() == "not": self.take("not"); return not self.factor()
        if self.tokens[self.index] == "(": self.take("("); value = self.expression(); self.take(")"); return value
        name = self.take()
        if name not in self.values: raise ValueError(f"Unknown selection: {name}")
        return self.values[name]

    def parse(self) -> bool:
        result = self.expression()
        if self.index != len(self.tokens): raise ValueError("Unexpected trailing condition")
        return result


def evaluate_detection(detection: dict[str, Any], event: dict[str, Any]) -> bool:
    condition = str(detection.get("condition", ""))
    names = [name for name in detection if name not in {"condition", "timeframe"}]
    if not condition or not names: raise ValueError("Detection needs selections and a condition")
    if any(token in condition.lower() for token in ("near ", " by ", " count(", " sum(", " min(", " max(", " avg(", "|")):
        raise ValueError("Correlation/aggregation conditions are not locally supported")
    values = {name: selection_match(detection[name], event) for name in names}
    return BooleanParser(expand_quantifiers(condition, names), values).parse()


def validate_detection(detection: dict[str, Any]) -> None:
    """Reject unsupported modifiers and syntax before a rule is called executable."""
    for name, selection in detection.items():
        if name in {"condition", "timeframe"}: continue
        mappings = selection if isinstance(selection, list) else [selection]
        for mapping in mappings:
            if isinstance(mapping, dict):
                for expression in mapping:
                    modifiers = str(expression).split("|")[1:]
                    if any(item.lower() not in SUPPORTED_MODIFIERS for item in modifiers):
                        raise ValueError(f"Unsupported modifier in {expression}")
    evaluate_detection(detection, {})


@dataclass(frozen=True)
class ExecutableMatch:
    alert_rule_id: str
    title: str
    severity: str
    environment: str
    solution_codes: tuple[str, ...]
    event: dict[str, Any]


def execute(rules: list[dict[str, Any]], events: list[dict[str, Any]]) -> list[ExecutableMatch]:
    output = []
    for rule in rules:
        detection = rule["detection"]
        for event in events:
            if evaluate_detection(detection, event):
                output.append(ExecutableMatch(rule["alert_rule_id"], rule["title"], rule.get("level", "unknown"), rule["environment"], tuple(rule.get("solution_codes", [])), event))
    return output
