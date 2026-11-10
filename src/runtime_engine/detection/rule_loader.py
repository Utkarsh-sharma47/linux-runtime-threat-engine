"""A declarative, allow-listed condition language, never Python eval."""

from importlib.resources import files
from pathlib import Path
from typing import Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, model_validator

from runtime_engine.events.schema import EventType, Severity


class Condition(BaseModel):
    model_config = ConfigDict(extra="forbid")
    field: Literal[
        "process_name",
        "parent_process_name",
        "executable_path",
        "file_path",
        "uid",
        "previous_uid",
        "network_destination",
    ]
    op: Literal["in", "not_in", "equals", "path_under"]
    value: str | int | list[str | int]

    @model_validator(mode="after")
    def valid_value(self) -> "Condition":
        if self.op in ("in", "not_in", "path_under") and not isinstance(self.value, list):
            raise ValueError("list operator requires a list")
        if self.op == "path_under" and (
            self.field not in ("executable_path", "file_path")
            or not isinstance(self.value, list)
            or not all(isinstance(v, str) and v.startswith("/") for v in self.value)
        ):
            raise ValueError("path_under requires absolute path roots and a path field")
        return self


class Rule(BaseModel):
    model_config = ConfigDict(extra="forbid")
    rule_id: str = Field(min_length=1)
    name: str
    description: str
    severity: Severity
    event_type: EventType
    conditions: list[Condition] = Field(min_length=1)
    enabled: bool = True
    mitre_reference: str | None = None


def load_rules(path: Path | None = None) -> list[Rule]:
    """Load bundled rules or a custom YAML file, rejecting duplicate IDs."""
    text = (
        path.read_text()
        if path
        else files("runtime_engine.data").joinpath("default_rules.yaml").read_text()
    )
    raw = yaml.safe_load(text)
    if not isinstance(raw, list):
        raise ValueError("rules YAML must be a list")
    rules = [Rule.model_validate(item) for item in raw]
    if len({r.rule_id for r in rules}) != len(rules):
        raise ValueError("duplicate rule IDs")
    return rules
