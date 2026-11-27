"""Tests for the Junos API catalog generator, run against scripts/catalog/fixtures/.

Run: uv run --with pyang==2.6.1 --with 'setuptools<81' --with pytest pytest scripts/catalog -q
"""

import gzip
import json
import pathlib

import pytest

import generate

FIXTURES = pathlib.Path(__file__).parent / "fixtures"


def _load(out_dir, stem):
    plain = out_dir / f"{stem}.json"
    if plain.exists():
        return json.loads(plain.read_text())
    return json.loads(gzip.decompress((out_dir / f"{stem}.json.gz").read_bytes()))


@pytest.fixture(scope="module")
def catalog(tmp_path_factory):
    out_dir = tmp_path_factory.mktemp("catalog")
    result = generate.main([str(FIXTURES), str(out_dir), "--notes", str(FIXTURES / "notes"), "--commit", "fixture"])
    assert result.skipped == [], "fixtures must resolve cleanly"
    return {"rpc": _load(out_dir, "rpc"), "config": _load(out_dir, "config")}


def _es_rpc(catalog, name):
    return catalog["rpc"]["families"]["junos-es"][name]


def test_rpc_has_cli_and_input(catalog):
    (variant,) = _es_rpc(catalog, "get-arp-table-information")
    assert variant["cli"] == "show arp"
    assert variant["description"] == "Show system Address Resolution Protocol table entries"
    assert {"name": "interface", "type": "string", "description": "Name of the interface"} in variant["input"]
    assert "all-chassis" in [arg["name"] for arg in variant["input"]]


def test_output_is_element_tree_only(catalog):
    (variant,) = _es_rpc(catalog, "get-arp-table-information")
    assert variant["output"] == {"arp-table-information": {"arp-table-entry": {"mac-address": {}}}}


def test_identical_variants_merge_trains(catalog):
    (variant,) = _es_rpc(catalog, "get-arp-table-information")
    assert variant["trains"] == ["23.1", "23.4"]


def test_changed_variant_splits(catalog):
    old, new = _es_rpc(catalog, "get-route-summary-information")
    assert old["trains"] == ["23.1"] and old["input"] == []
    assert new["trains"] == ["23.4"] and [arg["name"] for arg in new["input"]] == ["table"]


def test_evo_maps_to_junos_evo(catalog):
    (variant,) = catalog["rpc"]["families"]["junos-evo"]["get-arp-table-information"]
    assert variant["trains"] == ["25.4"]
    assert "system name-server" in catalog["config"]["families"]["junos-evo"]


def test_trains_below_23_1_ignored(catalog):
    assert catalog["rpc"]["trains"] == ["23.1", "23.4", "25.4"]
    assert "get-old-information" not in catalog["rpc"]["families"]["junos-es"]


def test_latest_R_within_train_wins(catalog):
    assert "get-r1-only-information" not in catalog["rpc"]["families"]["junos-es"]


def test_config_paths_flattened(catalog):
    paths = catalog["config"]["families"]["junos-es"]
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
    assert catalog["config"]["source"] == {"repo": "Juniper/yang", "commit": "fixture"}


def test_note_attached(catalog):
    (variant,) = _es_rpc(catalog, "get-arp-table-information")
    assert variant["note"] == "Example: `<get-arp-table-information/>`"
    (server,) = catalog["config"]["families"]["junos-es"]["system name-server"]
    assert server["note"] == "Order matters."
    (route_old, _) = _es_rpc(catalog, "get-route-summary-information")
    assert "note" not in route_old
