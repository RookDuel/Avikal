# RookDuel Avikal Backend Core

This package contains the archive engine behind the desktop app.

It is responsible for:

- archive creation and extraction
- metadata packing and validation
- chess/PGN control-plane encoding
- password and keyphrase protection
- Drand and Aavrit time-capsule metadata handling
- optional external PQC keyfile workflows

## Public Entry Points

Python API:

```python
from core.main import create_avk_file, extract_avk_file
```

CLI:

```bash
cd backend
python -m avikal_backend.cli --help
```

## Important Notes

- The supported source path uses Avikal's bundled chess core.
- The supported backend runtime does not rely on an external `python-chess` or `pychess` dependency.
- The `.avk` container is a ZIP-based outer format with strict validation through `avk_format.py`.

## Useful CLI Commands

```bash
python -m avikal_backend.cli encode document.pdf --password-prompt
python -m avikal_backend.cli encode document.pdf assets/ --password-prompt
python -m avikal_backend.cli decode document.avk --password-prompt
python -m avikal_backend.cli inspect document.avk --password-prompt
python -m avikal_backend.cli contents bundle.avk --password-prompt
python -m avikal_backend.cli validate document.avk
python -m avikal_backend.cli doctor
```

## Testing

From the repository root, targeted backend tests live in `backend/tests`.

Examples:

```bash
python -m pytest backend/tests/test_activity_audit.py -q
python -m pytest backend/tests/test_chess_recursive_variations.py -q
```

## License

Apache-2.0.
