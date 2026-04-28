"""Runtime directory and logging setup for the backend API."""

from __future__ import annotations

from dataclasses import dataclass
import logging
import logging.handlers
import os
from pathlib import Path
import sys
import tempfile


@dataclass(frozen=True)
class RuntimePaths:
    log_dir: Path
    preview_session_root: Path


def configure_windows_stdio() -> None:
    if sys.platform == "win32" and "pytest" not in sys.modules:
        import codecs

        sys.stdout = codecs.getwriter("utf-8")(sys.stdout.detach())
        sys.stderr = codecs.getwriter("utf-8")(sys.stderr.detach())


def _ensure_runtime_dirs(base_dir: Path) -> RuntimePaths:
    log_dir = base_dir / "logs"
    preview_root = base_dir / "preview_sessions"
    log_dir.mkdir(parents=True, exist_ok=True)
    preview_root.mkdir(parents=True, exist_ok=True)
    return RuntimePaths(log_dir, preview_root)


def initialise_runtime_paths() -> tuple[RuntimePaths, str | None]:
    user_data_dir = Path(os.getenv("AVIKAL_USER_DATA_DIR") or (Path.home() / ".avikal"))
    try:
        return _ensure_runtime_dirs(user_data_dir), None
    except OSError:
        fallback_dir = Path(tempfile.gettempdir()) / "avikal-runtime"
        return (
            _ensure_runtime_dirs(fallback_dir),
            f"Primary backend user-data directory was unavailable; using {fallback_dir}",
        )


def _create_file_handler(log_dir: Path) -> tuple[logging.Handler | None, str | None]:
    candidates = [
        log_dir / "avikal_backend.log",
        Path(tempfile.gettempdir()) / "avikal-runtime" / "logs" / f"avikal_backend_{os.getpid()}.log",
    ]

    for index, candidate in enumerate(candidates):
        try:
            candidate.parent.mkdir(parents=True, exist_ok=True)
            handler = logging.handlers.RotatingFileHandler(
                str(candidate),
                maxBytes=100 * 1024 * 1024,
                backupCount=5,
                encoding="utf-8",
            )
            if index == 0:
                return handler, None
            return handler, f"Primary backend log file was unavailable; using fallback log file {candidate}"
        except OSError:
            continue

    return None, "File logging is unavailable; continuing with console logging only."


def configure_logging(log_dir: Path) -> tuple[logging.Logger, str | None]:
    file_handler, file_logging_message = _create_file_handler(log_dir)

    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.INFO)
    console_handler.setFormatter(logging.Formatter("%(levelname)s: %(message)s"))

    handlers = [console_handler]
    if file_handler is not None:
        file_handler.setLevel(logging.DEBUG)
        file_handler.setFormatter(
            logging.Formatter(
                fmt="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
                datefmt="%Y-%m-%dT%H:%M:%S",
            )
        )
        handlers.insert(0, file_handler)

    logging.basicConfig(level=logging.DEBUG, handlers=handlers)
    return logging.getLogger("avikal.api"), file_logging_message
