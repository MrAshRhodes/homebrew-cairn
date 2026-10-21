"""Helpers shared by the test modules."""

from __future__ import annotations

import importlib.util
import os
import shutil
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

REPO_ROOT = Path(__file__).resolve().parent.parent
FIXTURES = Path(__file__).resolve().parent / "fixtures"

# Variables that change how the script behaves; tests must not inherit them.
_ISOLATED_ENV = ("GITHUB_ACTIONS", "GITHUB_OUTPUT", "GITHUB_STEP_SUMMARY", "GITHUB_TOKEN", "GH_TOKEN", "OPENSSL")


def load_script(name: str):
    path = REPO_ROOT / "scripts" / f"{name}.py"
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module  # dataclasses look their module up here
    spec.loader.exec_module(module)
    return module


bump_cask = load_script("bump_cask")


def scratch_dir() -> Path:
    """A fresh directory in the repository's ignored scratch area, never the system temp dir."""
    root = Path(os.environ.get("BUMP_TEST_SCRATCH") or REPO_ROOT / ".scratch" / "test-tmp")
    root.mkdir(parents=True, exist_ok=True)
    return Path(tempfile.mkdtemp(prefix="t-", dir=root))


class ScratchTestCase(unittest.TestCase):
    """Gives every test its own scratch directory and an environment free of CI settings."""

    def setUp(self) -> None:
        super().setUp()
        self.tmp = scratch_dir()
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        patcher = mock.patch.dict(os.environ)
        patcher.start()
        self.addCleanup(patcher.stop)
        for name in _ISOLATED_ENV:
            os.environ.pop(name, None)
