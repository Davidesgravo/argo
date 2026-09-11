import hashlib
import json
import random
from collections import Counter
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import httpx

from argo.config import CORPUS_PATH, CUTOFF_DATE, DATA_DIR, RESULTS_DIR, SEED, TEST_END_DATE
from argo.dataset.benign import HARD_CANDIDATES, POPULAR_CANDIDATES
from argo.dataset.datadog import (
    SamplePath,
    download_sample,
    ensure_repo,
    list_sample_paths,
    load_manifest,
)
from argo.dataset.fingerprint import fingerprint
from argo.dataset.registry import (
    Registry,
    RegistryError,
    RegistryLike,
    previous_version,
    versions_in_window,
)
from argo.dataset.select import diverse_order
from argo.dataset.waves import WAVES, matches_any_signature, signature, wave_for_date
from argo.extract.archive import (
    INSTALL_SCRIPTS,
    ArchiveError,
    PackageFiles,
    read_datadog_zip,
    read_npm_tgz,
)
from argo.jsonl import read_models, write_jsonl
from argo.schema import HistorySet, Sample, Split, Subgroup

SubgroupFn = Callable[[SamplePath, PackageFiles], Subgroup | None]
HISTORY_BENIGN_WINDOW = ("2023-01-01", "2024-12-31")
TEST_WINDOW = (CUTOFF_DATE, TEST_END_DATE)


@dataclass(frozen=True)
class Quotas:
    nato: int = 28
    compromesso: int = 12
    per_wave: int = 5
    popular: int = 20
    hard: int = 20
    history_malicious: int = 40
    history_compromised_max: int = 10
    history_benign_each: int = 5
    history_wave_extra: int = 5


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _wave_fn(subgroup: Subgroup) -> SubgroupFn:
    return lambda sp, pkg: subgroup if signature(subgroup, pkg) else None


def _not_wave(subgroup: Subgroup) -> SubgroupFn:
    return lambda sp, pkg: None if matches_any_signature(pkg) else subgroup


class CorpusBuilder:
    def __init__(
        self,
        data_dir: Path,
        registry: RegistryLike,
        manifest: dict[str, list[str] | None],
        download: Callable[[SamplePath], Path],
        seed: int = SEED,
        log: Callable[[str], None] = print,
    ) -> None:
        self.data_dir = data_dir.resolve()
        self.registry = registry
        self.manifest = manifest
        self.download = download
        self.rng = random.Random(seed)
        self.log = log
        self.seen_fp: set[str] = set()
        self.seen_names: set[str] = set()
        self.infos: dict[str, dict[str, Any]] = {}

    def _rel(self, p: Path) -> str:
        return str(p.resolve().relative_to(self.data_dir))

    def _prev_archive(self, name: str, prev: str | None) -> str | None:
        if prev is None:
            return None
        try:
            return self._rel(self.registry.tarball(name, prev))
        except (RegistryError, httpx.HTTPError) as e:
            self.log(f"  previous version unavailable {name}@{prev}: {e}")
            return None

    def _datadog_sample(
        self, sp: SamplePath, subgroup_for: SubgroupFn, split: Split, history_set: HistorySet | None
    ) -> Sample | None:
        if sp.name in self.seen_names:
            return None
        try:
            path = self.download(sp)
            pkg, info = read_datadog_zip(path)
        except (ArchiveError, httpx.HTTPError) as e:
            self.log(f"  skip {sp.id}: {e}")
            return None
        subgroup = subgroup_for(sp, pkg)
        if subgroup is None:
            return None
        fp = fingerprint(pkg, sp.name, sp.version)
        if fp in self.seen_fp:
            return None
        bad = self.manifest.get(sp.name, [sp.version])
        time_map = info.get("time") or {}
        prev = None if bad is None else previous_version(time_map, sp.version, exclude=bad)
        self.seen_fp.add(fp)
        self.seen_names.add(sp.name)
        self.infos[sp.id] = info
        return Sample(
            id=sp.id,
            name=sp.name,
            version=sp.version,
            prev_version=prev,
            label="malicious",
            subgroup=subgroup,
            date=sp.date,
            split=split,
            history_set=history_set,
            source="datadog",
            archive_path=self._rel(path),
            prev_archive_path=self._prev_archive(sp.name, prev),
            sha256=_sha256(path),
            fingerprint=fp,
        )

    def take_datadog(
        self,
        cands: Sequence[SamplePath],
        n: int,
        subgroup_for: SubgroupFn,
        split: Split,
        history_set: HistorySet | None = None,
        max_per_date: int = 2,
        label: str = "",
    ) -> list[Sample]:
        out: list[Sample] = []
        for sp in diverse_order(cands, lambda s: s.date, self.rng, max_per_date):
            if len(out) >= n:
                break
            s = self._datadog_sample(sp, subgroup_for, split, history_set)
            if s is not None:
                out.append(s)
                self.log(f"  + {label or s.subgroup} {s.id}")
        if len(out) < n:
            self.log(f"WARNING {label}: only {len(out)}/{n} samples")
        return out

    def _npm_sample(
        self,
        name: str,
        window: tuple[str, str],
        subgroup: Subgroup,
        split: Split,
        history_set: HistorySet | None,
        need_install: bool,
    ) -> Sample | None:
        if name in self.seen_names:
            return None
        try:
            time_map = self.registry.packument(name).get("time") or {}
            versions = versions_in_window(time_map, *window)
            if not versions:
                return None
            version = versions[-1]
            prev = previous_version(time_map, version)
            if prev is None:
                return None
            path = self.registry.tarball(name, version)
            pkg = read_npm_tgz(path.read_bytes())
            scripts = pkg.manifest().get("scripts") or {}
            has_install = isinstance(scripts, dict) and any(k in scripts for k in INSTALL_SCRIPTS)
            if has_install != need_install:
                return None
            prev_path = self.registry.tarball(name, prev)
        except (RegistryError, ArchiveError, httpx.HTTPError) as e:
            self.log(f"  skip {name}: {e}")
            return None
        fp = fingerprint(pkg, name, version)
        self.seen_names.add(name)
        self.seen_fp.add(fp)
        return Sample(
            id=f"{name}@{version}",
            name=name,
            version=version,
            prev_version=prev,
            label="benign",
            subgroup=subgroup,
            date=time_map[version][:10],
            split=split,
            history_set=history_set,
            source="npm",
            archive_path=self._rel(path),
            prev_archive_path=self._rel(prev_path),
            sha256=_sha256(path),
            fingerprint=fp,
        )

    def take_benign(
        self,
        names: Sequence[str],
        n: int,
        window: tuple[str, str],
        subgroup: Subgroup,
        split: Split,
        history_set: HistorySet | None,
        need_install: bool,
    ) -> list[Sample]:
        out: list[Sample] = []
        for name in names:
            if len(out) >= n:
                break
            s = self._npm_sample(name, window, subgroup, split, history_set, need_install)
            if s is not None:
                out.append(s)
                self.log(f"  + {subgroup} {s.id}")
        if len(out) < n:
            self.log(f"WARNING {subgroup}/{split}: only {len(out)}/{n} samples")
        return out

    def add_pairs(self, shai: list[Sample]) -> list[Sample]:
        pairs: list[Sample] = []
        for s in shai:
            if s.prev_version is None or s.prev_archive_path is None:
                self.log(f"WARNING no clean pair for {s.id}")
                continue
            time_map = self.infos.get(s.id, {}).get("time") or {}
            bad = self.manifest.get(s.name) or []
            prev_of_prev = previous_version(time_map, s.prev_version, exclude=bad)
            archive = self.data_dir / s.prev_archive_path
            try:
                pkg = read_npm_tgz(archive.read_bytes())
            except ArchiveError as e:
                self.log(f"WARNING bad clean archive for {s.id}: {e}")
                continue
            pair = Sample(
                id=f"{s.name}@{s.prev_version}",
                name=s.name,
                version=s.prev_version,
                prev_version=prev_of_prev,
                label="benign",
                subgroup="pulito_accoppiato",
                date=(time_map.get(s.prev_version) or s.date)[:10],
                split="test",
                source="npm",
                archive_path=s.prev_archive_path,
                prev_archive_path=self._prev_archive(s.name, prev_of_prev),
                sha256=_sha256(archive),
                fingerprint=fingerprint(pkg, s.name, s.prev_version),
                pair_id=s.id,
            )
            s.pair_id = pair.id
            pairs.append(pair)
        return pairs

    def build(self, paths: Sequence[SamplePath], q: Quotas = Quotas()) -> list[Sample]:  # noqa: B008
        post = [p for p in paths if CUTOFF_DATE <= p.date <= TEST_END_DATE]
        pre = [p for p in paths if p.date < CUTOFF_DATE]
        samples: list[Sample] = []
        shai_test: list[Sample] = []
        for w in WAVES:
            cands = [
                p for p in post if p.category == "compromised_lib" and w.start <= p.date <= w.end
            ]
            fn = _wave_fn(w.subgroup)
            shai_test += self.take_datadog(
                cands, q.per_wave, fn, "test", max_per_date=3, label=w.subgroup
            )
            if w.subgroup in ("shai_hulud_w1", "shai_hulud_w2"):
                hs: HistorySet = "w1" if w.subgroup == "shai_hulud_w1" else "w2"
                samples += self.take_datadog(
                    cands, q.history_wave_extra, fn, "history", hs, 3, f"history {w.subgroup}"
                )
        samples += shai_test + self.add_pairs(shai_test)
        outside = [p for p in post if wave_for_date(p.date) is None]
        samples += self.take_datadog(
            [p for p in outside if p.category == "compromised_lib"],
            q.compromesso,
            _not_wave("compromesso"),
            "test",
            label="compromesso",
        )
        samples += self.take_datadog(
            [p for p in post if p.category == "malicious_intent"],
            q.nato,
            _not_wave("nato_malevolo"),
            "test",
            label="nato_malevolo",
        )
        hist_comp = self.take_datadog(
            [p for p in pre if p.category == "compromised_lib"],
            q.history_compromised_max,
            _not_wave("compromesso"),
            "history",
            "base",
            label="history compromesso",
        )
        samples += hist_comp
        samples += self.take_datadog(
            [p for p in pre if p.category == "malicious_intent"],
            q.history_malicious - len(hist_comp),
            _not_wave("nato_malevolo"),
            "history",
            "base",
            label="history nato_malevolo",
        )
        samples += self.take_benign(
            POPULAR_CANDIDATES,
            q.popular,
            TEST_WINDOW,
            "benigno_popolare",
            "test",
            None,
            need_install=False,
        )
        samples += self.take_benign(
            HARD_CANDIDATES,
            q.hard,
            TEST_WINDOW,
            "benigno_difficile",
            "test",
            None,
            need_install=True,
        )
        samples += self.take_benign(
            POPULAR_CANDIDATES,
            q.history_benign_each,
            HISTORY_BENIGN_WINDOW,
            "benigno_popolare",
            "history",
            "base",
            need_install=False,
        )
        samples += self.take_benign(
            HARD_CANDIDATES,
            q.history_benign_each,
            HISTORY_BENIGN_WINDOW,
            "benigno_difficile",
            "history",
            "base",
            need_install=True,
        )
        return samples


def summarize(samples: Sequence[Sample]) -> dict[str, int]:
    return dict(sorted(Counter(f"{s.split}/{s.subgroup}" for s in samples).items()))


def build_corpus(data_dir: Path = DATA_DIR, quotas: Quotas = Quotas()) -> list[Sample]:  # noqa: B008
    cache, quarantine = data_dir / "cache", data_dir / "quarantine"
    headers = {"User-Agent": "argo-thesis-poc"}
    with httpx.Client(timeout=120, follow_redirects=True, headers=headers) as client:
        repo = cache / "datadog-repo"
        commit = ensure_repo(repo)
        builder = CorpusBuilder(
            data_dir,
            Registry(cache, client),
            load_manifest(client, cache),
            lambda sp: download_sample(sp, quarantine, client),
        )
        samples = builder.build(list_sample_paths(repo), quotas)
    write_jsonl(data_dir / "corpus.jsonl", [s.model_dump() for s in samples])
    meta = {
        "datadog_commit": commit,
        "seed": SEED,
        "built_at": datetime.now(UTC).isoformat(),
        "counts": summarize(samples),
    }
    (data_dir / "corpus_meta.json").write_text(json.dumps(meta, indent=2))
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    (RESULTS_DIR / "dataset_summary.json").write_text(json.dumps(meta, indent=2))
    return samples


def load_corpus(path: Path = CORPUS_PATH) -> list[Sample]:
    return read_models(path, Sample)
