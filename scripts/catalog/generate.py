"""Generate the embedded Junos API catalog (rpc.json, config.json) from a Juniper/yang checkout.

Usage: generate.py <yang-checkout> <out-dir> [--notes DIR] [--commit SHA] [--jobs N]
Run with: uv run --with pyang==2.6.1 --with 'setuptools<81' python scripts/catalog/generate.py ...

Handles the three Juniper/yang layouts:
  23.1-23.2  <train>/<rel>/{common,junos-es,junos-ex}/{rpc,conf}-with-extensions/*.yang
  23.4+      <train>/<rel>/native/conf-and-rpcs/{common,junos-es,...}/{rpc,conf}-with-extensions/models/
  EVO        <train>/<rel>-EVO/native/conf-and-rpcs/{common,rpc-with-extensions,...}/models/  (family junos-evo)
Only the newest R release per train is used; trains before 23.1 are ignored.
"""

import argparse
import concurrent.futures
import dataclasses
import gzip
import json
import os
import pathlib
import re
import subprocess
import sys
import tempfile

MIN_TRAIN = (23, 1)
FAMILIES = ("junos-es", "junos-ex")
EVO_FAMILY = "junos-evo"
KINDS = {"rpc": "rpcs", "conf": "config"}
PLAIN_LIMIT = 20 * 1024 * 1024  # ruling P1: plain .json up to 20 MB, else .json.gz
TRAIN_RE = re.compile(r"^(\d+)\.(\d+)$")
RELEASE_RE = re.compile(r"^(\d+\.\d+)R(\d+)(?:\.(\d+))?(-EVO)?$")
PLUGIN = pathlib.Path(__file__).resolve().parent / "junos_catalog.py"


@dataclasses.dataclass
class Job:
    """One pyang run: a family's rpc or conf modules for one train."""

    train: str
    family: str
    kind: str
    models: pathlib.Path
    common: pathlib.Path


@dataclasses.dataclass
class Result:
    """What main() wrote, for callers and tests."""

    files: dict
    skipped: list
    counts: dict


def _models_dir(path):
    models = path / "models"
    return models if models.is_dir() else path


def discover(checkout):
    """Yield a Job per (train, family, kind) from the newest R release of each train."""
    for train_dir in sorted(checkout.iterdir()):
        match = TRAIN_RE.match(train_dir.name)
        if not train_dir.is_dir() or not match or (int(match[1]), int(match[2])) < MIN_TRAIN:
            continue
        newest = {}  # is_evo -> (sort key, release dir)
        for release in train_dir.iterdir():
            rel = RELEASE_RE.match(release.name)
            if not release.is_dir() or not rel or rel[1] != train_dir.name:
                continue
            key = (int(rel[2]), int(rel[3] or 0))
            is_evo = rel[4] is not None
            if is_evo not in newest or key > newest[is_evo][0]:
                newest[is_evo] = (key, release)
        for is_evo, (_, release) in sorted(newest.items()):
            native = release / "native" / "conf-and-rpcs"
            base = native if native.is_dir() else release
            common = _models_dir(base / "common")
            family_dirs = {EVO_FAMILY: base} if is_evo else {family: base / family for family in FAMILIES}
            for family, family_dir in family_dirs.items():
                for kind in KINDS:
                    models = _models_dir(family_dir / f"{kind}-with-extensions")
                    if models.is_dir():
                        yield Job(train_dir.name, family, kind, models, common)


def run_pyang(job):
    """Run the junos-catalog pyang plugin over one job; return (job, parsed output, warnings)."""
    files = sorted(job.models.glob("*.yang"))
    with tempfile.TemporaryDirectory() as tmp:
        # --plugindir imports every .py in the dir, so give pyang a dir holding only the plugin.
        plugin_dir = pathlib.Path(tmp) / "plugin"
        plugin_dir.mkdir()
        (plugin_dir / PLUGIN.name).symlink_to(PLUGIN)
        out_file = pathlib.Path(tmp) / "out.json"
        cmd = ["pyang", "--plugindir", str(plugin_dir), "-f", "junos-catalog", "-o", str(out_file),
               "-p", str(job.common), "-p", str(job.models), *map(str, files)]
        proc = subprocess.run(cmd, capture_output=True, text=True)
        if not out_file.exists():
            reason = proc.stderr.strip().splitlines()[-1:] or ["no output"]
            return job, None, [f"{job.train} {job.family} {job.kind}: pyang failed: {reason[0]}"]
        data = json.loads(out_file.read_text())
    warnings = [f"{job.train} {job.family} {job.kind}: {s['module']}: {s['reason']}" for s in data["skipped"]]
    seen = set(data["modules"]) | {s["module"] for s in data["skipped"]}
    for path in files:
        name = path.name.split("@")[0].removesuffix(".yang")
        if name not in seen:
            warnings.append(f"{job.train} {job.family} {job.kind}: {name}: did not parse")
    return job, data, warnings


def merge(per_train):
    """per_train: {family: {train: {name: body}}} -> {family: {name: [variant, ...]}}.

    Consecutive trains (in the family's own train order) with an identical body share one variant.
    """
    families = {}
    for family, trains in sorted(per_train.items()):
        entries = {}
        previous = None
        for train in sorted(trains, key=_train_key):
            for name, body in trains[train].items():
                variants = entries.setdefault(name, [])
                last = variants[-1] if variants else None
                if last and last["body"] == body and last["trains"][-1] == previous:
                    last["trains"].append(train)
                else:
                    variants.append({"trains": [train], "body": body})
            previous = train
        families[family] = {
            name: [{"trains": v["trains"], **v["body"]} for v in variants]
            for name, variants in sorted(entries.items())
        }
    return families


def attach_notes(families, notes_dir, kind):
    """Add `note` from notes/<kind>/<name>.md (spaces as dashes) to every variant of an entry."""
    if notes_dir is None:
        return
    for entries in families.values():
        for name, variants in entries.items():
            note_file = notes_dir / kind / f"{name.replace(' ', '-')}.md"
            if note_file.is_file():
                note = note_file.read_text().strip()
                for variant in variants:
                    variant["note"] = note


def write_catalog(out_dir, stem, document):
    """Write <stem>.json if it fits PLAIN_LIMIT, else <stem>.json.gz; remove the other. Return (path, raw size)."""
    raw = json.dumps(document, separators=(",", ":"), sort_keys=True).encode()
    plain, packed = out_dir / f"{stem}.json", out_dir / f"{stem}.json.gz"
    keep, drop = (plain, packed) if len(raw) <= PLAIN_LIMIT else (packed, plain)
    keep.write_bytes(raw if keep is plain else gzip.compress(raw, compresslevel=9, mtime=0))
    drop.unlink(missing_ok=True)
    return keep, len(raw)


def _train_key(train):
    major, minor = train.split(".")
    return int(major), int(minor)


def _git_commit(checkout):
    proc = subprocess.run(["git", "-C", str(checkout), "rev-parse", "HEAD"], capture_output=True, text=True)
    return proc.stdout.strip() if proc.returncode == 0 else "unknown"


def main(argv=None):
    """Generate the catalog; print skipped modules and counts. Returns a Result."""
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("checkout", type=pathlib.Path)
    parser.add_argument("out_dir", type=pathlib.Path)
    parser.add_argument("--notes", type=pathlib.Path)
    parser.add_argument("--commit", help="Juniper/yang commit (default: git HEAD of checkout)")
    parser.add_argument("--jobs", type=int, default=min(8, os.cpu_count() or 1))
    args = parser.parse_args(argv)

    jobs = list(discover(args.checkout))
    if not jobs:
        parser.error(f"no Junos YANG trains >= 23.1 found under {args.checkout}")
    per_kind = {kind: {} for kind in KINDS}
    skipped = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.jobs) as pool:
        for job, data, warnings in pool.map(run_pyang, jobs):
            skipped.extend(warnings)
            if data is not None:
                per_kind[job.kind].setdefault(job.family, {})[job.train] = data[KINDS[job.kind]]

    source = {"repo": "Juniper/yang", "commit": args.commit or _git_commit(args.checkout)}
    trains = sorted({job.train for job in jobs}, key=_train_key)
    args.out_dir.mkdir(parents=True, exist_ok=True)
    files, counts = {}, {}
    for kind, stem, notes_kind in (("rpc", "rpc", "rpc"), ("conf", "config", "config")):
        families = merge(per_kind[kind])
        attach_notes(families, args.notes, notes_kind)
        path, raw_size = write_catalog(args.out_dir, stem, {"source": source, "trains": trains, "families": families})
        files[path.name] = {"raw": raw_size, "written": path.stat().st_size}
        counts[stem] = {family: len(entries) for family, entries in families.items()}

    for warning in skipped:
        print(f"warning: skipped {warning}", file=sys.stderr)
    print(json.dumps({"files": files, "counts": counts, "skipped": len(skipped)}, indent=2))
    return Result(files, skipped, counts)


if __name__ == "__main__":
    main()
