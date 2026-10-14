"""Declarative rule evaluation for the Aegis detection engine.

Rules live in rules.json - no detection logic is hardcoded in Python. A rule is a tree of
criteria joined by AND / OR. Missing fields never match, so rules written for data the agent
does not collect yet (e.g. command_line, planned for Phase 7) are safe to ship.
"""
import json
import re
from typing import Any, Callable

SEVERITIES = ("LOW", "MEDIUM", "HIGH", "CRITICAL")


def _s(v: Any) -> str:
    return str(v).lower()


OPERATORS: dict[str, Callable[[Any, Any], bool]] = {
    "equals": lambda f, v: _s(f) == _s(v),
    "not_equals": lambda f, v: _s(f) != _s(v),
    "startswith": lambda f, v: _s(f).startswith(_s(v)),
    "endswith": lambda f, v: _s(f).endswith(_s(v)),
    "contains": lambda f, v: _s(v) in _s(f),
    "contains_any": lambda f, v: any(_s(x) in _s(f) for x in v),
    "contains_all": lambda f, v: all(_s(x) in _s(f) for x in v),
    "in": lambda f, v: _s(f) in {_s(x) for x in v},
    "regex": lambda f, v: re.search(v, str(f), re.IGNORECASE) is not None,
    "gt": lambda f, v: float(f) > float(v),
    "lt": lambda f, v: float(f) < float(v),
}


class RuleError(ValueError):
    pass


def _validate(node: dict, where: str) -> None:
    if "criteria" in node:
        if node.get("condition", "AND") not in ("AND", "OR"):
            raise RuleError(f"{where}: condition must be AND or OR")
        if not node["criteria"]:
            raise RuleError(f"{where}: criteria must not be empty")
        for i, child in enumerate(node["criteria"]):
            _validate(child, f"{where}.criteria[{i}]")
        return
    for key in ("field", "operator", "value"):
        if key not in node:
            raise RuleError(f"{where}: missing '{key}'")
    if node["operator"] not in OPERATORS:
        raise RuleError(f"{where}: unknown operator '{node['operator']}'")
    if node["operator"] == "regex":
        re.compile(node["value"])  # fail at load time, not at event time


def _eval(node: dict, event: dict) -> bool:
    if "criteria" in node:
        results = (_eval(c, event) for c in node["criteria"])
        return all(results) if node.get("condition", "AND") == "AND" else any(results)
    value = event.get(node["field"])
    if value is None:
        return False
    try:
        return OPERATORS[node["operator"]](value, node["value"])
    except (TypeError, ValueError):
        return False


class RuleSet:
    def __init__(self, rules: list[dict]):
        seen = set()
        self.rules = []
        for r in rules:
            for key in ("rule_id", "name", "severity", "criteria"):
                if key not in r:
                    raise RuleError(f"rule {r.get('rule_id', '?')}: missing '{key}'")
            if r["rule_id"] in seen:
                raise RuleError(f"duplicate rule_id {r['rule_id']}")
            seen.add(r["rule_id"])
            if r["severity"] not in SEVERITIES:
                raise RuleError(f"{r['rule_id']}: severity must be one of {SEVERITIES}")
            _validate(r, r["rule_id"])
            if r.get("enabled", True):
                self.rules.append(r)

    @classmethod
    def load(cls, path: str) -> "RuleSet":
        with open(path, "r", encoding="utf-8") as fh:
            return cls(json.load(fh))

    def match(self, event: dict) -> list[dict]:
        return [r for r in self.rules if _eval(r, event)]
