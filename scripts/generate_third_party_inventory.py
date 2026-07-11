"""Generate the dependency inventory shipped with Avikal distributions."""

from __future__ import annotations

import json
import subprocess
from importlib import metadata
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / ".app-build" / "THIRD_PARTY_NOTICES.generated.md"


def _npm_packages(lock_path: Path, ecosystem: str) -> list[tuple[str, str, str, str]]:
    document = json.loads(lock_path.read_text(encoding="utf-8"))
    rows: list[tuple[str, str, str, str]] = []
    for package_path, record in (document.get("packages") or {}).items():
        if not package_path or not isinstance(record, dict):
            continue
        name = record.get("name") or package_path.rsplit("node_modules/", 1)[-1]
        version = record.get("version")
        if not name or not version:
            continue
        license_name = record.get("license") or "SEE PACKAGE LICENSE"
        rows.append((ecosystem, str(name), str(version), str(license_name)))
    return rows


def _python_packages() -> list[tuple[str, str, str, str]]:
    rows: list[tuple[str, str, str, str]] = []
    for distribution in metadata.distributions():
        name = distribution.metadata.get("Name")
        if not name:
            continue
        license_name = (
            distribution.metadata.get("License-Expression")
            or distribution.metadata.get("License")
            or "SEE PACKAGE LICENSE"
        )
        rows.append(("Python", name, distribution.version, license_name.strip() or "SEE PACKAGE LICENSE"))
    return rows


def _rust_packages() -> list[tuple[str, str, str, str]]:
    manifest = ROOT / "backend" / "native" / "avikal_backend_native" / "Cargo.toml"
    completed = subprocess.run(
        ["cargo", "metadata", "--locked", "--format-version", "1", "--manifest-path", str(manifest)],
        check=True,
        capture_output=True,
        text=True,
        timeout=120,
    )
    document = json.loads(completed.stdout)
    return [
        ("Rust", item["name"], item["version"], item.get("license") or "SEE CRATE LICENSE")
        for item in document.get("packages", [])
    ]


def main() -> None:
    rows = []
    rows.extend(_npm_packages(ROOT / "package-lock.json", "JavaScript root"))
    rows.extend(_npm_packages(ROOT / "frontend" / "package-lock.json", "JavaScript frontend"))
    rows.extend(_npm_packages(ROOT / "backend" / "scripts" / "package-lock.json", "JavaScript drand helper"))
    rows.extend(_python_packages())
    rows.extend(_rust_packages())
    unique_rows = sorted(set(rows), key=lambda row: (row[0].lower(), row[1].lower(), row[2]))

    lines = [
        "# Avikal Packaged Third-Party Inventory",
        "",
        "This inventory is generated from the locked dependency graphs used to build this distribution.",
        "The authoritative license text remains the license file shipped by each component.",
        "",
        "| Ecosystem | Package | Version | Declared license |",
        "|---|---|---:|---|",
    ]
    for ecosystem, name, version, license_name in unique_rows:
        safe = [value.replace("|", "\\|").replace("\n", " ") for value in (ecosystem, name, version, license_name)]
        lines.append(f"| {safe[0]} | {safe[1]} | {safe[2]} | {safe[3]} |")
    lines.extend([
        "",
        "## Bundled OpenSSL",
        "",
        "Avikal packages OpenSSL 3.5 under Apache-2.0. Its complete LICENSE.txt is included with the PQC runtime.",
        "",
    ])
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT.write_text("\n".join(lines), encoding="utf-8")
    print(f"Generated {OUTPUT} with {len(unique_rows)} dependency records")


if __name__ == "__main__":
    main()
