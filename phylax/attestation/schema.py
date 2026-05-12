"""
phylax/attestation/schema.py

Canonical SSSA schema validation utilities.

The SSSA schema is defined as Pydantic models in phylax.protocol. This module
adds runtime validation helpers, version compatibility checks, and a
JSON-schema export for documentation / external consumers.
"""

from __future__ import annotations

import json
from typing import Optional, Tuple

from pydantic import ValidationError

from phylax.protocol import SSSA


SUPPORTED_SCHEMA_VERSIONS = {"1.0.0"}
CURRENT_SCHEMA_VERSION    = "1.0.0"


def validate_sssa(payload: dict) -> Tuple[bool, Optional[str], Optional[SSSA]]:
    """
    Validate a raw dict against the SSSA schema.

    Returns a tuple of (is_valid, error_message_or_None, parsed_sssa_or_None).
    """
    # Schema-version gate
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
    """Return the JSON Schema for the SSSA model (for docs / external use)."""
    return SSSA.model_json_schema() if hasattr(SSSA, "model_json_schema") else SSSA.schema()


def write_json_schema(path: str) -> None:
    """Write the SSSA JSON schema to a file."""
    with open(path, "w", encoding="utf-8") as f:
        json.dump(export_json_schema(), f, indent=2, sort_keys=True)
