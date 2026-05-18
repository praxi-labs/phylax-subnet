from __future__ import annotations

import json

from pydantic import ValidationError

from phylax.protocol import SCHEMA_VERSION, SSSA

CURRENT_SCHEMA_VERSION = SCHEMA_VERSION
SUPPORTED_SCHEMA_VERSIONS = {"1.0.0", "1.1.0"}


def validate_sssa(payload: dict) -> tuple[bool, str | None, SSSA | None]:
    """Validate a raw dict against the SSSA schema."""
    version = (
        payload.get("run_metadata", {}).get("schema_version")
        or payload.get("attestation", {}).get("schema_version")
        or CURRENT_SCHEMA_VERSION
    )
    if version not in SUPPORTED_SCHEMA_VERSIONS:
        return False, f"Unsupported schema_version: {version}", None

    try:
        sssa = SSSA(**payload)
    except ValidationError as exc:
        return False, f"SSSA validation error: {exc}", None

    return True, None, sssa


def export_json_schema() -> dict:
    return SSSA.model_json_schema() if hasattr(SSSA, "model_json_schema") else SSSA.schema()


def write_json_schema(path: str) -> None:
    with open(path, "w", encoding="utf-8") as f:
        json.dump(export_json_schema(), f, indent=2, sort_keys=True)
