"""pyang plugin: emit the RPCs and configuration paths of Junos YANG modules as JSON.

Used by generate.py as `pyang --plugindir scripts/catalog -f junos-catalog ...`. Output:
{"modules": [...], "skipped": [{"module", "reason"}],
 "rpcs": {name: {cli, description, input, output}},
 "config": {"space joined path": {kind, type, description, range, units}}}
"""

import json

from pyang import error, plugin

DDL_EXTENSIONS = "junos-common-ddl-extensions"
# Junos lets any value be an apply-path variable; this union member is noise.
VARIABLE_PATTERN = "<.*>|$.*"
DATA_KEYWORDS = ("container", "list", "leaf", "leaf-list", "anyxml", "anydata")
# A current node using a deprecated grouping is a status nit, not a broken module.
NON_FATAL_ERRORS = {"BAD_STATUS_REFERENCE"}
# Every Junos container repeats these (`uses apply-advanced`); keep them only at the top level.
APPLY_NODES = {"apply-groups", "apply-groups-except", "apply-macro"}
# These lists mirror the root hierarchy; keep only their direct children.
COLLAPSED_LISTS = {"logical-systems", "tenants"}


def pyang_plugin_init():
    """Register the junos-catalog output format with pyang."""
    plugin.register_plugin(JunosCatalogPlugin())


class JunosCatalogPlugin(plugin.PyangPlugin):
    """Output format `junos-catalog`."""

    def add_output_format(self, fmts):
        self.multiple_modules = True
        fmts["junos-catalog"] = self

    def emit(self, ctx, modules, fd):
        broken = _modules_with_errors(ctx)
        result = {"modules": [], "skipped": [], "rpcs": {}, "config": {}}
        for module in modules:
            if module.arg in broken:
                result["skipped"].append({"module": module.arg, "reason": broken[module.arg]})
                continue
            result["modules"].append(module.arg)
            for rpc in module.i_children:
                if rpc.keyword == "rpc":
                    result["rpcs"][rpc.arg] = _rpc_entry(rpc)
            if module.arg.endswith("-conf-root"):
                configuration = next(c for c in module.i_children if c.arg == "configuration")
                _walk_config(configuration, [], result["config"])
        json.dump(result, fd, sort_keys=True)


def _modules_with_errors(ctx):
    """Map module name -> first error message, for modules with hard (non-warning) errors."""
    broken = {}
    for pos, tag, args in ctx.errors:
        if error.is_warning(error.err_level(tag)) or tag in NON_FATAL_ERRORS or pos.top is None:
            continue
        name = getattr(pos.top, "i_modulename", pos.top.arg)
        broken.setdefault(name, f"{pos.label()}: {error.err_to_str(tag, args)}")
    return broken


def _description(stmt):
    found = stmt.search_one("description")
    return found.arg.strip() if found is not None else None


def _data_children(stmt):
    """Data-node children, looking through choice and case."""
    for child in getattr(stmt, "i_children", []):
        if child.keyword in ("choice", "case"):
            yield from _data_children(child)
        elif child.keyword in DATA_KEYWORDS:
            yield child


def _is_variable(type_stmt):
    pattern = type_stmt.search_one("pattern")
    return type_stmt.arg == "string" and pattern is not None and pattern.arg == VARIABLE_PATTERN


def _members(type_stmt):
    """Union members without the apply-path variable placeholder."""
    if type_stmt.arg != "union":
        return [type_stmt]
    members = []
    for member in type_stmt.search("type"):
        if not _is_variable(member):
            members.extend(_members(member))
    return members or [type_stmt]


def _type_name(type_stmt):
    name = type_stmt.arg.split(":")[-1]
    if name == "enumeration":
        return "enumeration: " + " | ".join(enum.arg for enum in type_stmt.search("enum"))
    return name


def _type_info(leaf):
    """(type string, range) for a leaf or leaf-list."""
    type_stmt = leaf.search_one("type")
    if type_stmt is None:
        return None, None
    members = _members(type_stmt)
    ranges = [m.search_one("range").arg for m in members if m.search_one("range") is not None]
    return " | ".join(_type_name(m) for m in members), (ranges[0] if ranges else None)


def _rpc_entry(rpc):
    command = rpc.search_one((DDL_EXTENSIONS, "command"))
    input_stmt = rpc.search_one("input")
    output_stmt = rpc.search_one("output")
    return {
        "cli": command.arg if command is not None else None,
        "description": _description(rpc),
        "input": _input_args(input_stmt, []) if input_stmt is not None else [],
        "output": _element_tree(output_stmt) if output_stmt is not None else {},
    }


def _input_args(stmt, prefix):
    args = []
    for child in _data_children(stmt):
        name = prefix + [child.arg]
        if child.keyword in ("container", "list"):
            args.extend(_input_args(child, name))
            continue
        type_name, _ = _type_info(child)
        args.append({"name": " ".join(name), "type": type_name, "description": _description(child)})
    return args


def _element_tree(stmt):
    return {child.arg: _element_tree(child) for child in _data_children(stmt)}


def _walk_config(stmt, prefix, out):
    for child in _data_children(stmt):
        if not prefix and child.arg == "groups":
            continue  # groups repeats the whole tree
        if prefix and child.arg in APPLY_NODES:
            continue
        path = prefix + [child.arg]
        type_name, value_range = (None, None)
        if child.keyword in ("leaf", "leaf-list"):
            type_name, value_range = _type_info(child)
        units = child.search_one("units")
        out[" ".join(path)] = {
            "kind": child.keyword,
            "type": type_name,
            "description": _description(child),
            "range": value_range,
            "units": units.arg if units is not None else None,
        }
        if prefix and prefix[0] in COLLAPSED_LISTS:
            continue
        _walk_config(child, path, out)
