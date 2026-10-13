"""Every `from moesoc.x import name` must name something module x defines.

GUI modules need PySide6, which the sandbox test run cannot import, so a wrong
import there would only show up on Windows. This check reads the source instead.
"""

from __future__ import annotations

import ast
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PACKAGE = ROOT / "moesoc"


def _module_path(module: str) -> Path | None:
    base = ROOT.joinpath(*module.split("."))
    for candidate in (base.with_suffix(".py"), base / "__init__.py"):
        if candidate.exists():
            return candidate
    return None


def _top_level_names(path: Path) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    names: set[str] = set()
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            names.add(node.name)
        elif isinstance(node, ast.Assign):
            for target in node.targets:
                names |= {n.id for n in ast.walk(target) if isinstance(n, ast.Name)}
        elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
            names.add(node.target.id)
        elif isinstance(node, (ast.Import, ast.ImportFrom)):
            names |= {(a.asname or a.name).split(".")[0] for a in node.names}
    return names


def test_internal_from_imports_resolve():
    problems = []
    sources = [*PACKAGE.rglob("*.py"), *(ROOT / "scripts").glob("*.py"), ROOT / "app.py"]
    for source in sources:
        tree = ast.parse(source.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if not (isinstance(node, ast.ImportFrom) and node.module):
                continue
            if not node.module.startswith("moesoc"):
                continue
            target = _module_path(node.module)
            if target is None:
                problems.append(f"{source.name}: module {node.module} not found")
                continue
            defined = _top_level_names(target)
            for alias in node.names:
                if alias.name == "*" or alias.name in defined:
                    continue
                if _module_path(f"{node.module}.{alias.name}") is not None:
                    continue  # importing a submodule
                problems.append(f"{source.name}: {node.module} has no {alias.name}")
    assert problems == []


def test_icon_exists_with_every_windows_size():
    """Read the ICO directory directly (no imaging library needed)."""
    import struct

    from moesoc.core.config import AppConfig

    data = AppConfig.default().icon_path.read_bytes()
    reserved, kind, count = struct.unpack_from("<HHH", data, 0)
    assert (reserved, kind) == (0, 1)  # an icon file
    sizes = {data[6 + 16 * i] or 256 for i in range(count)}  # width byte, 0 means 256
    assert {16, 24, 32, 48, 256} <= sizes


def test_every_version_string_matches_the_package():
    """The app, pyproject, the EXE version resource and the installer must agree."""
    from moesoc import __version__

    files = {
        "pyproject.toml": f'version = "{__version__}"',
        "packaging/version_info.txt": f'StringStruct("ProductVersion", "{__version__}")',
        "packaging/MoeSOC.iss": f'#define AppVersion "{__version__}"',
    }
    for name, expected in files.items():
        assert expected in (ROOT / name).read_text(encoding="utf-8"), name
    numbers = tuple(int(n) for n in __version__.split("."))
    vs = (ROOT / "packaging/version_info.txt").read_text(encoding="utf-8")
    assert f"filevers=({', '.join(map(str, numbers))}, 0)" in vs
