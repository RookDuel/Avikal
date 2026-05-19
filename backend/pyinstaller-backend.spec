# -*- mode: python ; coding: utf-8 -*-

from pathlib import Path

from PyInstaller.utils.hooks import collect_data_files, collect_submodules


project_root = Path(SPEC).resolve().parent
backend_src = project_root / "src"

datas = collect_data_files("certifi")
datas += [
    (str(project_root / "src" / "avikal_backend" / "wordlists" / "wordlist_hi_2048_v1.txt"), "avikal_backend/wordlists"),
    (str(project_root / "src" / "avikal_backend" / "wordlists" / "wordlist_hi_roman_2048_v1.txt"), "avikal_backend/wordlists"),
]
datas += [
    (str(project_root / "scripts" / "drand_timelock_helper.mjs"), "scripts"),
]

hiddenimports = []
for package_name in (
    "avikal_backend",
    "uvicorn",
    "fastapi",
    "starlette",
    "pydantic",
    "anyio",
    "multipart",
    "jwt",
):
    hiddenimports += collect_submodules(package_name)

a = Analysis(
    [str(project_root / "api_server.py")],
    pathex=[str(project_root), str(backend_src)],
    binaries=[],
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
    optimize=0,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name="avikal-backend",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    console=True,
)

coll = COLLECT(
    exe,
    a.binaries,
    a.datas,
    strip=False,
    upx=False,
    upx_exclude=[],
    name="backend",
)
