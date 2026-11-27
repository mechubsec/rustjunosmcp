"""Generate the embedded Junos API catalog (rpc-<family>.json.gz, config-<family>.json.gz) from a Juniper/yang checkout.

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
KINDS = {"rpc": "rpcs", "conf": "config"}  # job kind -> plugin output key
STEMS = {"rpc": "rpc", "conf": "config"}  # job kind -> file stem and gap "kind"
SHA_RE = re.compile(r"^[0-9a-f]{40}$")
TRAIN_RE = re.compile(r"^(\d+)\.(\d+)$")
RELEASE_RE = re.compile(r"^(\d+\.\d+)R(\d+)(?:\.(\d+))?(-EVO)?$")
PLUGIN = pathlib.Path(__file__).resolve().parent / "junos_catalog.py"

_SYNTAX_DEBUG = "Juniper YANG syntax error: stray 'DEBUG - Unhandled Scenario in emit_list_key()' line"
_EX_SHRINK = "upstream publishes fewer modules"
# Known holes in Juniper/yang, keyed (train, family, kind, module); module "*" covers the whole job.
# Each lands in the data as a gap. A job that yields no data and is not listed here as "*" is fatal.
KNOWN_GAPS = {
    ("23.1", "junos-es", "conf", "junos-es-conf-wlan"):
        "Juniper YANG syntax error: unescaped quote in junos:pattern-message",
    ("24.2", "junos-es", "conf", "junos-es-conf-logical-systems"): _SYNTAX_DEBUG,
    ("24.2", "junos-es", "conf", "junos-es-conf-services"): _SYNTAX_DEBUG,
    ("24.2", "junos-es", "conf", "junos-es-conf-tenants"): _SYNTAX_DEBUG,
    # junos-ex conf drops from 33 modules (23.4) to 6 from 24.2 on; routing-instances and most protocols vanish.
    **{(train, "junos-ex", "conf", "*"): _EX_SHRINK for train in ("24.2", "24.4", "25.2", "25.4", "26.2")},
}


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
    gaps: list
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
    """Run the junos-catalog pyang plugin over one job.

    Returns (job, data or None, [(module, reason), ...]); data is None when pyang wrote nothing
    or emitted no module at all.
    """
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
        data = json.loads(out_file.read_text()) if out_file.exists() else None
    errors = [line for line in proc.stderr.splitlines() if ": error: " in line]
    if data is None or not data["modules"]:
        return job, None, [("*", f"pyang produced no data: {(errors or ['no output'])[0]}")]
    missing = [(s["module"], s["reason"]) for s in data["skipped"]]
    seen = set(data["modules"]) | {s["module"] for s in data["skipped"]}
    for path in files:
        name = path.name.split("@")[0].removesuffix(".yang")
        if name not in seen:
            reason = next((line for line in errors if line.startswith(str(path))), "did not parse")
            missing.append((name, reason))
    return job, data, missing


def merge(per_train, gap_trains):
    """per_train: {family: {train: {name: body}}} -> {family: {name: [variant, ...]}}.

    Consecutive trains (in the family's own train order) with an identical body share one variant.
    An entry missing from a train in gap_trains[family] (data known incomplete) is carried through
    that train unchanged instead of being read as removed.
    """
    families = {}
    for family, trains in sorted(per_train.items()):
        entries = {}
        previous = None
        for train in sorted(trains, key=_train_key):
            present = trains[train]
            for name, body in present.items():
                variants = entries.setdefault(name, [])
                last = variants[-1] if variants else None
                if last and last["body"] == body and last["trains"][-1] == previous:
                    last["trains"].append(train)
                else:
                    variants.append({"trains": [train], "body": body})
            if train in gap_trains.get(family, ()):
                for name, variants in entries.items():
                    if name not in present and variants[-1]["trains"][-1] == previous:
                        variants[-1]["trains"].append(train)
            previous = train
        families[family] = {
            name: [{"trains": v["trains"], **v["body"]} for v in variants]
            for name, variants in sorted(entries.items())
        }
    return families


COLLAPSED_NOTES = {
    "logical-systems": "Contains the full root hierarchy for each logical system; look up the root path instead.",
    "tenants": "Contains the full root hierarchy for each tenant; look up the root path instead.",
}


def attach_notes(entries, notes_dir, kind):
    """Add `note` to every variant of an entry: the collapse note for logical-systems/tenants (config),
    then notes/<kind>/<name>.md (spaces as dashes), joined by a blank line."""
    for name, variants in entries.items():
        parts = [COLLAPSED_NOTES[name]] if kind == "config" and name in COLLAPSED_NOTES else []
        note_file = notes_dir / kind / f"{name.replace(' ', '-')}.md" if notes_dir else None
        if note_file and note_file.is_file():
            parts.append(note_file.read_text().strip())
        if parts:
            for variant in variants:
                variant["note"] = "\n\n".join(parts)


def intern_outputs(entries):
    """Replace each variant's output tree with an index into the returned list of distinct trees."""
    outputs, index = [], {}
    for variants in entries.values():
        for variant in variants:
            key = json.dumps(variant["output"], sort_keys=True)
            if key not in index:
                index[key] = len(outputs)
                outputs.append(variant["output"])
            variant["output"] = index[key]
    return outputs


def write_catalog(out_dir, stem, document):
    """Write <stem>.json.gz (ruling P8: always gzip) and drop a stale plain <stem>.json. Return (path, raw size)."""
    raw = json.dumps(document, separators=(",", ":"), sort_keys=True).encode()
    path = out_dir / f"{stem}.json.gz"
    path.write_bytes(gzip.compress(raw, compresslevel=9, mtime=0))
    (out_dir / f"{stem}.json").unlink(missing_ok=True)
    return path, len(raw)


def _train_key(train):
    major, minor = train.split(".")
    return int(major), int(minor)


def _source_commit(parser, commit, checkout):
    """The Juniper/yang commit: --commit, else the checkout's git HEAD; must be a full SHA."""
    if commit is None:
        proc = subprocess.run(["git", "-C", str(checkout), "rev-parse", "HEAD"], capture_output=True, text=True)
        commit = proc.stdout.strip() if proc.returncode == 0 else ""
    if not SHA_RE.match(commit):
        parser.error(f"need a 40-hex Juniper/yang commit (--commit or a git checkout), got {commit!r}")
    return commit


def main(argv=None):
    """Generate the catalog; print skipped modules and counts. Returns a Result."""
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("checkout", type=pathlib.Path)
    parser.add_argument("out_dir", type=pathlib.Path)
    parser.add_argument("--notes", type=pathlib.Path)
    parser.add_argument("--commit", help="Juniper/yang commit (default: git HEAD of checkout)")
    parser.add_argument("--jobs", type=int, default=min(8, os.cpu_count() or 1))
    args = parser.parse_args(argv)

    commit = _source_commit(parser, args.commit, args.checkout)
    jobs = list(discover(args.checkout))
    if not jobs:
        parser.error(f"no Junos YANG trains >= 23.1 found under {args.checkout}")
    per_kind = {kind: {} for kind in KINDS}
    gaps, fatal = [], []
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.jobs) as pool:
        for job, data, missing in pool.map(run_pyang, jobs):
            job_key = (job.train, job.family, job.kind)
            known = {module: reason for (*key, module), reason in KNOWN_GAPS.items() if tuple(key) == job_key}
            if data is None and "*" not in known:
                fatal.append(f"{' '.join(job_key)}: {missing[0][1]}")
            if data is not None and "*" in known:
                missing.append(("*", known["*"]))
            for module, reason in missing:
                gaps.append({"train": job.train, "family": job.family, "kind": STEMS[job.kind],
                             "module": module, "reason": known.get(module, reason)})
            per_kind[job.kind].setdefault(job.family, {})[job.train] = data[KINDS[job.kind]] if data else {}
    if fatal:
        for failure in fatal:
            print(f"error: {failure}", file=sys.stderr)
        sys.exit("error: pyang produced no data for jobs not in KNOWN_GAPS")

    source = {"repo": "Juniper/yang", "commit": commit}
    trains = sorted({job.train for job in jobs}, key=_train_key)
    args.out_dir.mkdir(parents=True, exist_ok=True)
    files, counts = {}, {}
    for kind, stem in STEMS.items():
        gap_trains = {}
        for gap in gaps:
            if gap["kind"] == stem:
                gap_trains.setdefault(gap["family"], set()).add(gap["train"])
        for family, entries in merge(per_kind[kind], gap_trains).items():
            attach_notes(entries, args.notes, stem)
            family_gaps = [g for g in gaps if g["kind"] == stem and g["family"] == family]
            document = {"source": source, "trains": trains, "families": {family: entries}, "gaps": family_gaps}
            if kind == "rpc":
                document["outputs"] = intern_outputs(entries)
            path, raw_size = write_catalog(args.out_dir, f"{stem}-{family}", document)
            files[path.name] = {"raw": raw_size, "written": path.stat().st_size}
            counts[f"{stem}-{family}"] = len(entries)

    for gap in gaps:
        print(f"gap: {gap['train']} {gap['family']} {gap['kind']} {gap['module']}: {gap['reason']}", file=sys.stderr)
    print(json.dumps({"files": files, "counts": counts, "gaps": len(gaps)}, indent=2))
    return Result(files, gaps, counts)


if __name__ == "__main__":
    main()
