"""Configuration values for the FastAPI backend."""

from __future__ import annotations

import os
from typing import List


DEFAULT_ALLOWED_CORS_ORIGINS = [
    "http://localhost:5173",
    "http://127.0.0.1:5173",
    "http://localhost:4173",
    "http://127.0.0.1:4173",
]


def parse_allowed_cors_origins() -> List[str]:
    raw = os.getenv("AVIKAL_ALLOWED_ORIGINS", "").strip()
    if not raw:
        return DEFAULT_ALLOWED_CORS_ORIGINS.copy()

    origins = [origin.strip() for origin in raw.split(",") if origin.strip()]
    return origins or DEFAULT_ALLOWED_CORS_ORIGINS.copy()


ALLOWED_CORS_ORIGINS = parse_allowed_cors_origins()
