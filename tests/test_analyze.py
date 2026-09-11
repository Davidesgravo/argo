from pathlib import Path
from typing import Any

import pytest

from argo.analyze import analyze, fetch_from_registry, from_upload, parse_spec
from argo.dataset.registry import RegistryError
from tests.helpers import make_tgz, pkg_json


@pytest.mark.parametrize(
    "spec,expected",
    [
        ("react", ("react", None)),
        ("react@18.2.0", ("react", "18.2.0")),
        ("@scope/pkg", ("@scope/pkg", None)),
        ("@scope/pkg@1.0.0-beta.1", ("@scope/pkg", "1.0.0-beta.1")),
        ("  lodash@4.17.21 ", ("lodash", "4.17.21")),
    ],
)
def test_parse_spec(spec, expected):
    assert parse_spec(spec) == expected


@pytest.mark.parametrize("spec", ["", "a@b@c", "@scope", "has space"])
def test_parse_spec_invalid(spec):
    with pytest.raises(ValueError):
        parse_spec(spec)


class OneRegistry:
    def __init__(self, root: Path) -> None:
        self.root = root

    def packument(self, name: str) -> dict[str, Any]:
        if name != "demo":
            raise RegistryError(name)
        return {
            "dist-tags": {"latest": "1.1.0"},
            "time": {"1.0.0": "2025-01-01T00:00:00Z", "1.1.0": "2025-02-01T00:00:00Z"},
        }

    def tarball(self, name: str, version: str) -> Path:
        scripts = {"postinstall": "node x.js"} if version == "1.1.0" else {}
        return make_tgz(
            self.root / f"{version}.tgz",
            {"package.json": pkg_json("demo", version, scripts=scripts), "x.js": "eval(1)"},
        )


def test_fetch_latest_with_previous(tmp_path):
    f = fetch_from_registry("demo", OneRegistry(tmp_path))
    assert (f.version, f.prev_version) == ("1.1.0", "1.0.0") and f.old is not None


def test_analyze_uses_threshold(tmp_path):
    f = fetch_from_registry("demo@1.1.0", OneRegistry(tmp_path))
    d, s, flagged = analyze(f, threshold=1.0)
    assert "[NEW]" in d.text and s >= 2.0 and flagged is True
    assert analyze(f, threshold=None)[2] is None


def test_from_upload(tmp_path):
    new = make_tgz(tmp_path / "n.tgz", {"package.json": pkg_json("up", "2.0.0")}).read_bytes()
    old = make_tgz(tmp_path / "o.tgz", {"package.json": pkg_json("up", "1.9.0")}).read_bytes()
    f = from_upload(new, old)
    assert (f.name, f.version, f.prev_version) == ("up", "2.0.0", "1.9.0")
    assert from_upload(new, None).old is None


def test_ui_modules_import():
    import argo.ui.common  # noqa: F401
    import argo.ui.views.analizza  # noqa: F401
