"""Model -> plain dict/JSON (used by the JSON report and the HTML/MD builders)."""
from __future__ import annotations
import dataclasses
import json
import typing
from enum import Enum

from ..core.models import ScanResult


def _plain(obj):
    if isinstance(obj, Enum):
        return obj.value
    if dataclasses.is_dataclass(obj):
        return {k: _plain(v) for k, v in dataclasses.asdict(obj).items()}
    if isinstance(obj, (list, tuple)):
        return [_plain(x) for x in obj]
    if isinstance(obj, dict):
        return {k: _plain(v) for k, v in obj.items()}
    return obj


def to_dict(result: ScanResult) -> dict:
    return _plain(result)


def to_json(result: ScanResult, *, indent: int = 2) -> str:
    return json.dumps(to_dict(result), indent=indent, default=str)


def _build(tp, val):
    if val is None:
        return None
    origin = typing.get_origin(tp)
    if origin is typing.Union:                      # Optional[X]
        args = [a for a in typing.get_args(tp) if a is not type(None)]
        return _build(args[0], val) if args else val
    if dataclasses.is_dataclass(tp):
        hints = typing.get_type_hints(tp)
        fields = {f.name for f in dataclasses.fields(tp)}
        return tp(**{k: _build(hints[k], v) for k, v in val.items() if k in fields})
    if origin in (list, tuple):
        elem = (typing.get_args(tp) or (object,))[0]
        return [_build(elem, x) for x in val]
    if isinstance(tp, type) and issubclass(tp, Enum):
        return tp(val)
    return val


def from_dict(d: dict) -> ScanResult:
    """Rebuild a ScanResult from the dict produced by to_dict (for `report`)."""
    return _build(ScanResult, d)
