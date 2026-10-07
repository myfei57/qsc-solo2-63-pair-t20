#!/usr/bin/env python3
"""Run the shard-log tests without a pytest install.

Usage: ``python3 tools/run_shardlog_tests.py``. Under a normal environment the
project uses real pytest (``python3 -m pytest tests/shardlog``); this runner is
the fallback for locked-down boxes that only ship the standard library. It
injects a tiny ``pytest`` module plus the ``tmp_path`` fixture before importing
the test files.
"""

from __future__ import annotations

import importlib.util
import shutil
import sys
import tempfile
import traceback
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import types  # noqa: E402

from tests.shardlog import _pytest_compat  # noqa: E402

_fake = types.ModuleType("pytest")
_fake.raises = _pytest_compat.raises


class _Mark:
    @staticmethod
    def skip(*_args, **_kwargs):
        def decorator(function):
            function.__skip__ = True
            return function

        return decorator


_fake.mark = _Mark()
sys.modules["pytest"] = _fake

TESTS_DIR = ROOT / "tests" / "shardlog"
TEST_FILES = sorted(TESTS_DIR.glob("test_*.py"))


def _load_module(path: Path):
    spec = importlib.util.spec_from_file_location(path.stem, path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def main() -> int:
    total = passed = failed = skipped = 0
    failures: list[str] = []
    tmp_root = Path(tempfile.mkdtemp(prefix="shardlog-tests-"))
    try:
        for test_file in TEST_FILES:
            module = _load_module(test_file)
            functions = [
                (name, value)
                for name, value in vars(module).items()
                if name.startswith("test_") and callable(value)
            ]
            for name, function in functions:
                total += 1
                label = f"{test_file.name}::{name}"
                if getattr(function, "__skip__", False):
                    skipped += 1
                    continue
                case_dir = tmp_root / f"{test_file.stem}_{name}"
                case_dir.mkdir(parents=True, exist_ok=True)
                try:
                    if "tmp_path" in function.__code__.co_varnames:
                        function(case_dir)
                    else:
                        function()
                    passed += 1
                    print(f"PASS {label}")
                except Exception:  # noqa: BLE001 - report every failure
                    failed += 1
                    failures.append(label)
                    print(f"FAIL {label}")
                    traceback.print_exc()
    finally:
        shutil.rmtree(tmp_root, ignore_errors=True)

    print(f"\n{passed} passed, {failed} failed, {skipped} skipped, {total} total")
    if failures:
        print("failed:", ", ".join(failures))
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
