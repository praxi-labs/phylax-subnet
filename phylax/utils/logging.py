"""
phylax/utils/logging.py

Structured logging helpers shared across the miner, validator, and pipeline.

We intentionally use the stdlib `logging` module rather than wrapping
bittensor's logger — bt.logging is used at neuron boundaries, while
phylax internals stay portable and testable without a bittensor dependency.
"""

from __future__ import annotations

import logging
import os
import sys
from typing import Optional

_DEFAULT_FORMAT = (
    "%(asctime)s [%(levelname)s] %(name)s — %(message)s"
)
_DATE_FORMAT = "%Y-%m-%dT%H:%M:%S"

_CONFIGURED = False


def _configure_root() -> None:
    global _CONFIGURED
    if _CONFIGURED:
        return

    level = os.getenv("PHYLAX_LOG_LEVEL", "INFO").upper()
    root = logging.getLogger()
    root.setLevel(level)

    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(logging.Formatter(_DEFAULT_FORMAT, datefmt=_DATE_FORMAT))
    if not root.handlers:
        root.addHandler(handler)

    _CONFIGURED = True


def get_logger(name: Optional[str] = None) -> logging.Logger:
    """Return a configured logger. Safe to call repeatedly."""
    _configure_root()
    return logging.getLogger(name or "phylax")
