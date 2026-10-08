"""JSON number semantics shared by contract checks and report projections."""

from typing import Any


def is_json_integer(value: object) -> bool:
    if isinstance(value, float):
        return value.is_integer()
    return isinstance(value, int) and not isinstance(value, bool)


def normalize_json_integer(value: Any) -> Any:
    return int(value) if is_json_integer(value) else value
