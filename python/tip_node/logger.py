"""node/logger.py — Structured logger for TIP Protocol."""
# Author:    Dinesh Mendhe <chairman@theailab.org>
from __future__ import annotations
import logging
import os
import sys

_LEVEL_MAP = {"debug": logging.DEBUG, "info": logging.INFO,
              "warning": logging.WARNING, "error": logging.ERROR}

_fmt = logging.Formatter(
    fmt="[%(asctime)s] [%(levelname)-5s] [%(name)s] %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)

def get_logger(name: str) -> logging.Logger:
    level_name = os.environ.get("TIP_LOG_LEVEL", "info").lower()
    level = _LEVEL_MAP.get(level_name, logging.INFO)
    logger = logging.getLogger(f"tip.{name}")
    if not logger.handlers:
        handler = logging.StreamHandler(sys.stdout)
        handler.setFormatter(_fmt)
        logger.addHandler(handler)
    logger.setLevel(level)
    logger.propagate = False
    return logger
