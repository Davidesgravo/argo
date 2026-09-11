from pathlib import Path
from typing import Any

from argo.dataset.build import CorpusBuilder
from argo.dataset.datadog import SamplePath
from argo.dataset.registry import RegistryError
from tests.helpers import make_datadog_zip, make_tgz, pkg_json

T = "T00:00:00Z"


class FakeRegistry:
    def __init__(
        self,
        root: Path,
        packages: dict[str, dict[str, dict[str, str]]],
        times: dict[str, dict[str, str]],
    ) -> None:
        self.root, self.packages, self.times = root, packages, times

    def packument(self, name: str) -> dict[str, Any]:
        if name not in self.times:
            raise RegistryError(name)
        return {"time": self.times[name], "versions": {v: {} for v in self.packages[name]}}

    def tarball(self, name: str, version: str) -> Path:
        files = self.packages.get(name, {}).get(version)
        if files is None:
            raise RegistryError(f"{name}@{version}")
        return make_tgz(self.root / "cache" / f"{name}-{version}.tgz", files)


def _sp(cat: str, name: str, version: str, date: str) -> SamplePath:
    return SamplePath(
        cat, name, version, date, f"samples/npm/{cat}/{name}/{version}/{date}-{name}.zip"
    )


def _setup(tmp_path: Path):
    zips: dict[str, Path] = {}

    def add_zip(sp: SamplePath, files: dict[str, str], time: dict[str, str]) -> None:
        zips[sp.id] = make_datadog_zip(
            tmp_path / "quarantine" / f"{sp.name}-{sp.version}.zip",
            files,
            {"time": time},
            pkgdir=sp.name,
            password=None,
        )

    w1 = _sp("compromised_lib", "host-a", "1.0.1", "2025-09-15")
    add_zip(
        w1,
        {
            "package.json": pkg_json("host-a", "1.0.1", scripts={"postinstall": "node bundle.js"}),
            "bundle.js": "payload",
            "dist/a.js": "a",
        },
        {"1.0.0": "2025-08-01" + T, "1.0.1": "2025-09-15" + T},
    )
    evil_a = _sp("malicious_intent", "evil-a", "9.9.9", "2025-03-01")
    evil_b = _sp("malicious_intent", "evil-b", "9.9.9", "2025-03-02")
    for sp in (evil_a, evil_b):
        add_zip(
            sp,
            {
                "package.json": pkg_json(sp.name, "9.9.9", scripts={"preinstall": "node i.js"}),
                "i.js": f"send('{sp.name}')",
            },
            {"9.9.9": sp.date + T},
        )
    registry = FakeRegistry(
        tmp_path,
        packages={
            "host-a": {
                "1.0.0": {"package.json": pkg_json("host-a", "1.0.0")},
                "0.9.0": {"package.json": pkg_json("host-a", "0.9.0")},
            },
            "good": {
                "2.0.0": {
                    "package.json": pkg_json("good", "2.0.0", scripts={"postinstall": "node b.js"})
                },
                "2.1.0": {
                    "package.json": pkg_json("good", "2.1.0", scripts={"postinstall": "node b.js"})
                },
            },
        },
        times={"good": {"2.0.0": "2025-01-10" + T, "2.1.0": "2025-04-01" + T}},
    )
    manifest: dict[str, list[str] | None] = {"host-a": ["1.0.1"], "evil-a": None, "evil-b": None}
    builder = CorpusBuilder(
        tmp_path, registry, manifest, lambda sp: zips[sp.id], log=lambda _: None
    )
    return builder, w1, evil_a, evil_b


def test_wave_sample_gets_clean_previous_version(tmp_path):
    builder, w1, *_ = _setup(tmp_path)
    [s] = builder.take_datadog([w1], 1, lambda sp, pkg: "shai_hulud_w1", "test")
    assert s.subgroup == "shai_hulud_w1" and s.label == "malicious"
    assert s.prev_version == "1.0.0" and s.prev_archive_path is not None
    assert not Path(s.archive_path).is_absolute()


def test_campaign_clones_are_deduplicated(tmp_path):
    builder, _, evil_a, evil_b = _setup(tmp_path)
    got = builder.take_datadog([evil_a, evil_b], 2, lambda sp, pkg: "nato_malevolo", "test")
    assert len(got) == 1 and got[0].prev_version is None


def test_pairs_link_both_ways(tmp_path):
    builder, w1, *_ = _setup(tmp_path)
    shai = builder.take_datadog([w1], 1, lambda sp, pkg: "shai_hulud_w1", "test")
    [pair] = builder.add_pairs(shai)
    assert pair.subgroup == "pulito_accoppiato" and pair.label == "benign"
    assert pair.version == "1.0.0" and pair.pair_id == shai[0].id and shai[0].pair_id == pair.id


def test_benign_install_script_filter(tmp_path):
    builder, *_ = _setup(tmp_path)
    window = ("2025-01-01", "2026-08-31")
    none = builder.take_benign(
        ["good"], 1, window, "benigno_popolare", "test", None, need_install=False
    )
    assert none == []
    [hard] = builder.take_benign(
        ["good"], 1, window, "benigno_difficile", "test", None, need_install=True
    )
    assert hard.version == "2.1.0" and hard.prev_version == "2.0.0"
