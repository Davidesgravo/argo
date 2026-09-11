import json
import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

from argo.config import ROOT, RUNS_DIR
from argo.run.runner import RunConfig


def run_command(cfg: RunConfig) -> list[str]:
    prefix = ["caffeinate", "-i"] if shutil.which("caffeinate") else []
    cmd = [
        *prefix,
        sys.executable,
        "-m",
        "argo.cli",
        "run",
        "--run-id",
        cfg.run_id,
        "--models",
        *cfg.models,
        "--prompts",
        *cfg.prompts,
        "--mode",
        cfg.mode,
        "--yes",
    ]
    if cfg.subgroups:
        cmd += ["--subgroups", *cfg.subgroups]
    if cfg.limit:
        cmd += ["--limit", str(cfg.limit)]
    return cmd


def start_run(cfg: RunConfig, runs_dir: Path = RUNS_DIR) -> int:
    out = runs_dir / cfg.run_id
    out.mkdir(parents=True, exist_ok=True)
    with (out / "run.log").open("a") as log:
        proc = subprocess.Popen(
            run_command(cfg), stdout=log, stderr=subprocess.STDOUT, cwd=ROOT, start_new_session=True
        )
    (out / "pid").write_text(str(proc.pid))
    return proc.pid


def run_progress(run_dir: Path) -> tuple[int, int]:
    preds = run_dir / "predictions.jsonl"
    done = sum(1 for line in preds.open() if line.strip()) if preds.exists() else 0
    cfg = run_dir / "config.json"
    total = int(json.loads(cfg.read_text()).get("n_jobs", 0)) if cfg.exists() else 0
    return done, total


def is_running(run_dir: Path) -> bool:
    pid_file = run_dir / "pid"
    if not pid_file.exists():
        return False
    pid = int(pid_file.read_text())
    try:
        finished, _ = os.waitpid(pid, os.WNOHANG)  # reaps our own zombie children
        if finished == pid:
            return False
    except ChildProcessError:
        pass  # not our child (e.g. started by a previous UI session)
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def list_runs(runs_dir: Path = RUNS_DIR) -> list[dict[str, Any]]:
    out = []
    for d in sorted(p for p in runs_dir.glob("*") if (p / "config.json").exists()):
        done, total = run_progress(d)
        out.append({"run_id": d.name, "done": done, "total": total, "running": is_running(d)})
    return out
