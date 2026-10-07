"""Minimal pytest shim.

The CI image runs these tests under real pytest. In environments without
pytest installed (a locked-down box, a scratch container) the same test files
remain runnable directly with ``python3 -m tests.shardlog.test_...`` because
this module provides the tiny subset of the pytest API the shard-log tests use:
``raises`` and the ``tmp_path`` fixture (a ``pathlib.Path`` temp directory).
"""

from __future__ import annotations

import contextlib
import shutil
import tempfile
from pathlib import Path


class raises:  # noqa: N801 - mirrors pytest.raises naming
    def __init__(self, expected: type[BaseException]) -> None:
        self.expected = expected
        self.value: BaseException | None = None

    def __enter__(self) -> "raises":
        return self

    def __exit__(self, exc_type, exc, _tb) -> bool:
        if exc_type is None:
            raise AssertionError(f"expected {self.expected.__name__}, nothing raised")
        if not issubclass(exc_type, self.expected):
            return False
        self.value = exc
        return True


@contextlib.contextmanager
def tmp_path():
    path = Path(tempfile.mkdtemp(prefix="shardlog-test-"))
    try:
        yield path
    finally:
        shutil.rmtree(path, ignore_errors=True)


class _PytestShim:
    raises = staticmethod(raises)
    mark = type("mark", (), {"skip": staticmethod(lambda *a, **k: None)})()


pytest = _PytestShim()

