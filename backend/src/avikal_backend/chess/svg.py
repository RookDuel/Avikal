"""
SPDX-License-Identifier: Apache-2.0
Copyright (c) 2026 Atharva Sen Barai.
"""

def _svg_box(size: int) -> str:
    return (
        f"<svg xmlns='http://www.w3.org/2000/svg' "
        f"width='{size}' height='{size}' viewBox='0 0 {size} {size}'></svg>"
    )


def piece(*, size: int = 45, **_kwargs) -> str:
    return _svg_box(size)


def board(*, size: int = 400, **_kwargs) -> str:
    return _svg_box(size)
"""
SPDX-License-Identifier: Apache-2.0
Copyright (c) 2026 Atharva Sen Barai.
"""
