"""Tests for the Junos API catalog generator, run against scripts/catalog/fixtures/.

Run: uv run --with pyang==2.6.1 --with 'setuptools<81' --with pytest pytest scripts/catalog -q
"""

import gzip
import json
import pathlib

import shutil

import pytest

import generate

FIXTURES = pathlib.Path(__file__).parent / "fixtures"
FAKE_SHA = "0123456789abcdef0123456789abcdef01234567"
BROKEN_YANG = "module broken {\n  this is not yang\n"


def _load(out_dir, stem):
    return json.loads(gzip.decompress((out_dir / f"{stem}.json.gz").read_bytes()))


def _generate(checkout, out_dir, commit=FAKE_SHA):
    return generate.main([str(checkout), str(out_dir), "--notes", str(FIXTURES / "notes"), "--commit", commit])


def _fixture_copy(tmp_path):
    checkout = tmp_path / "yang"
    shutil.copytree(FIXTURES, checkout)
    return checkout


@pytest.fixture(scope="module")
def catalog(tmp_path_factory):
    out_dir = tmp_path_factory.mktemp("catalog")
    result = _generate(FIXTURES, out_dir)
    assert result.gaps == [], "fixtures must resolve cleanly"
    files = sorted(path.name for path in out_dir.iterdir())
    families = ("junos-es", "junos-evo")
    return {
        "files": files,
        "rpc": {family: _load(out_dir, f"rpc-{family}") for family in families},
        "config": {family: _load(out_dir, f"config-{family}") for family in families},
    }


def _rpc(catalog, name, family="junos-es"):
    """Variants of an RPC with `output` resolved from the file's interned outputs."""
    document = catalog["rpc"][family]
    return [{**v, "output": document["outputs"][v["output"]]} for v in document["families"][family][name]]


def _config(catalog, family="junos-es"):
    return catalog["config"][family]["families"][family]


def test_rpc_has_cli_and_input(catalog):
    (variant,) = _rpc(catalog, "get-arp-table-information")
    assert variant["cli"] == "show arp"
    assert variant["description"] == "Show system Address Resolution Protocol table entries"
    assert {"name": "interface", "type": "string", "description": "Name of the interface"} in variant["input"]
    assert "all-chassis" in [arg["name"] for arg in variant["input"]]


def test_output_is_element_tree_only(catalog):
    (variant,) = _rpc(catalog, "get-arp-table-information")
    assert variant["output"] == {"arp-table-information": {"arp-table-entry": {"mac-address": {}}}}


def test_identical_variants_merge_trains(catalog):
    (variant,) = _rpc(catalog, "get-arp-table-information")
    assert variant["trains"] == ["23.1", "23.4"]


def test_changed_variant_splits(catalog):
    old, new = _rpc(catalog, "get-route-summary-information")
    assert old["trains"] == ["23.1"] and old["input"] == []
    assert new["trains"] == ["23.4"] and [arg["name"] for arg in new["input"]] == ["table"]


def test_evo_maps_to_junos_evo(catalog):
    (variant,) = _rpc(catalog, "get-arp-table-information", "junos-evo")
    assert variant["trains"] == ["25.4"]
    assert "system name-server" in _config(catalog, "junos-evo")


def test_trains_below_23_1_ignored(catalog):
    assert catalog["rpc"]["junos-es"]["trains"] == ["23.1", "23.4", "25.4"]
    assert "get-old-information" not in catalog["rpc"]["junos-es"]["families"]["junos-es"]


def test_latest_R_within_train_wins(catalog):
    assert "get-r1-only-information" not in catalog["rpc"]["junos-es"]["families"]["junos-es"]


def test_config_paths_flattened(catalog):
    paths = _config(catalog)
    (server,) = paths["system name-server"]
    assert server["kind"] == "list" and server["type"] is None
    assert server["trains"] == ["23.1", "23.4"]
    (limit,) = paths["system processes-limit"]
    assert limit == {
        "trains": ["23.1", "23.4"],
        "kind": "leaf",
        "type": "uint32",
        "description": "Maximum processes",
        "range": "1 .. 64",
        "units": "processes",
    }
    assert not any(path.startswith("groups") for path in paths)
    assert "apply-groups" in paths and "system apply-groups" not in paths
    assert "system legacy" in paths  # deprecated grouping use does not skip the module
    assert catalog["config"]["junos-es"]["source"] == {"repo": "Juniper/yang", "commit": FAKE_SHA}


def test_note_attached(catalog):
    (variant,) = _rpc(catalog, "get-arp-table-information")
    assert variant["note"] == "Example: `<get-arp-table-information/>`"
    (server,) = _config(catalog)["system name-server"]
    assert server["note"] == "Order matters."
    (route_old, _) = _rpc(catalog, "get-route-summary-information")
    assert "note" not in route_old


def test_every_note_names_a_catalog_entry(tmp_path):
    notes = tmp_path / "notes"
    shutil.copytree(FIXTURES / "notes", notes)
    (notes / "rpc" / "get-no-such-rpc.md").write_text("orphan")
    with pytest.raises(SystemExit, match="get-no-such-rpc"):
        generate.main([str(FIXTURES), str(tmp_path / "out"), "--notes", str(notes), "--commit", FAKE_SHA])


def test_outputs_interned(catalog):
    document = catalog["rpc"]["junos-es"]
    entries = document["families"]["junos-es"]
    summary = entries["get-route-summary-information"][0]["output"]
    (brief,) = entries["get-route-summary-brief-information"]
    assert isinstance(summary, int) and summary == brief["output"]
    assert document["outputs"][summary] == {"route-summary-information": {}}
    assert len(document["outputs"]) == len({json.dumps(tree, sort_keys=True) for tree in document["outputs"]})


def test_logical_systems_collapsed(catalog):
    paths = _config(catalog)
    assert {"logical-systems", "logical-systems name", "logical-systems system"} <= paths.keys()
    assert not any(path.startswith(("logical-systems system ", "tenants system ")) for path in paths)
    (lsys,) = paths["logical-systems"]
    assert lsys["note"] == "Contains the full root hierarchy for each logical system; look up the root path instead."
    (tenants,) = paths["tenants"]
    assert tenants["note"] == (
        "Contains the full root hierarchy for each tenant; look up the root path instead.\n\nTenant note."
    )


def test_one_file_per_family(catalog):
    assert catalog["files"] == [
        "config-junos-es.json.gz",
        "config-junos-evo.json.gz",
        "rpc-junos-es.json.gz",
        "rpc-junos-evo.json.gz",
    ]
    for kind in ("rpc", "config"):
        for family, document in catalog[kind].items():
            assert list(document["families"]) == [family]
            assert document["trains"] == ["23.1", "23.4", "25.4"]


def test_files_are_gzip_json(tmp_path):
    out_dir = tmp_path / "out"
    _generate(FIXTURES, out_dir)
    for path in out_dir.iterdir():
        assert path.read_bytes()[:2] == b"\x1f\x8b", path.name
        assert json.loads(gzip.decompress(path.read_bytes()))["gaps"] == []


def test_skipped_module_recorded_as_gap(tmp_path):
    checkout = _fixture_copy(tmp_path)
    route = checkout / "23.4/23.4R2/native/conf-and-rpcs/junos-es/rpc-with-extensions/models"
    (route / "junos-es-rpc-route@2023-01-01.yang").write_text(BROKEN_YANG)
    result = _generate(checkout, tmp_path / "out")
    document = _load(tmp_path / "out", "rpc-junos-es")
    (gap,) = document["gaps"]
    assert gap["train"] == "23.4" and gap["family"] == "junos-es" and gap["kind"] == "rpc"
    assert gap["module"] == "junos-es-rpc-route" and gap["reason"]
    assert result.gaps == [gap]
    # Absent only because its module was skipped: the range runs through the gap train.
    (variant,) = document["families"]["junos-es"]["get-route-summary-information"]
    assert variant["trains"] == ["23.1", "23.4"]
    assert _load(tmp_path / "out", "config-junos-es")["gaps"] == []


def test_unexpected_job_failure_exits_nonzero(tmp_path):
    checkout = _fixture_copy(tmp_path)
    models = checkout / "23.4/23.4R2/native/conf-and-rpcs/junos-es/rpc-with-extensions/models"
    for path in models.iterdir():
        path.write_text(BROKEN_YANG)
    with pytest.raises(SystemExit) as exit_info:
        _generate(checkout, tmp_path / "out")
    assert exit_info.value.code not in (0, None)
    assert not (tmp_path / "out").exists()


def test_commit_must_be_sha(tmp_path):
    with pytest.raises(SystemExit) as exit_info:
        _generate(FIXTURES, tmp_path / "out", commit="unknown")
    assert exit_info.value.code != 0
