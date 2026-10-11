# SPDX-License-Identifier: Apache-2.0
"""Bounded schema validation and declarative manifest semantic checks.

Fresh SDK implementation of the accepted contracts. Atlas domain policy,
installation trust and source-version qualification are consumer responsibilities.
"""
from functools import lru_cache
from importlib.resources import files
import hashlib
import json
import math
import re
from urllib.parse import urlsplit

MAX_METADATA_BYTES = 256 * 1024
SCHEMA_DIGESTS = {
    "connector-manifest-v1.1": "c61320ec17f100f6f747b2f517eb7e98168778223c9164c168744eb0b1c8b958",
    "aip-v1": "db34dc0d484a83998da9aeec4517648d60ca4ee6ddd4ed7657c4c0031133189d",
    "connector-manifest-v1": "e1305db294527ea6645c9bc17d0325c3cf05adf1aa23d3084f6899f0bed896c0",
}


class ContractError(ValueError):
    """Safe diagnostic only; never include an input value or upstream exception."""

    def __init__(self, code):
        self.code = code
        super().__init__(code)


def strict_json(raw, *, maximum=MAX_METADATA_BYTES):
    def pairs(rows):
        result = {}
        for name, value in rows:
            if name in result:
                raise ContractError("duplicate_metadata_key")
            result[name] = value
        return result

    def number(value):
        parsed = float(value)
        if not math.isfinite(parsed):
            raise ContractError("invalid_metadata_number")
        return parsed

    def constant(_value):
        raise ContractError("invalid_metadata_number")

    try:
        size = len(raw.encode("utf-8") if isinstance(raw, str) else raw)
        if size > maximum:
            raise ContractError("metadata_too_large")
        return json.loads(raw, object_pairs_hook=pairs, parse_float=number, parse_constant=constant)
    except ContractError:
        raise
    except (TypeError, ValueError, UnicodeError, RecursionError):
        raise ContractError("invalid_metadata") from None


def schema_bytes(name):
    if name not in SCHEMA_DIGESTS:
        raise ContractError("unknown_schema")
    raw = files("atlas_connector_sdk").joinpath("schemas", name + ".schema.json").read_bytes()
    if hashlib.sha256(raw).hexdigest() != SCHEMA_DIGESTS[name]:
        raise ContractError("sdk_contract_changed")
    return raw


@lru_cache(maxsize=3)
def validator(name):
    from jsonschema import Draft202012Validator, FormatChecker
    schema = strict_json(schema_bytes(name))
    Draft202012Validator.check_schema(schema)
    return Draft202012Validator(schema, format_checker=FormatChecker())


def version_key(value):
    """SemVer precedence without interpreting arbitrary package expressions."""
    expression = r"(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:-([0-9A-Za-z.-]+))?(?:\+[0-9A-Za-z.-]+)?"
    match = re.fullmatch(expression, value) if isinstance(value, str) else None
    if match is None:
        raise ContractError("invalid_version")
    prerelease = match[4]
    parts = []
    if prerelease is not None:
        for part in prerelease.split("."):
            if not part or (part.isdigit() and len(part) > 1 and part.startswith("0")):
                raise ContractError("invalid_version")
            parts.append((0, int(part)) if part.isdigit() else (1, part))
    return (int(match[1]), int(match[2]), int(match[3]), prerelease is None, tuple(parts))


def version_in_range(value, bounds):
    return version_key(bounds["minimum"]) <= version_key(value) < version_key(bounds["exclusive_maximum"])


def validate_manifest(manifest):
    """Validate wire shape and references, independently of Atlas activation policy."""
    from jsonschema.exceptions import ValidationError
    try:
        schema_name = {"1.0": "connector-manifest-v1", "1.1": "connector-manifest-v1.1"}.get(manifest.get("manifest_version"))
        if schema_name is None:
            raise ContractError("invalid_manifest")
        validator(schema_name).validate(manifest)
        version_key(manifest["version"])
        for bounds in [manifest["compatibility"]["sdk"], manifest["compatibility"]["atlas"],
                       manifest["compatibility"]["runtime"]["baseline"]]:
            if version_key(bounds["minimum"]) >= version_key(bounds["exclusive_maximum"]):
                raise ContractError("invalid_version_range")
        for url in [manifest["display"]["documentation_uri"], manifest["distribution"]["asset_uri"],
                    manifest["distribution"]["provenance"]["evidence_uri"]]:
            parsed = urlsplit(url)
            if (parsed.scheme != "https" or not parsed.hostname or parsed.username is not None
                    or parsed.password is not None or parsed.port not in {None, 443}
                    or parsed.fragment or any(ord(char) < 33 for char in url)):
                raise ContractError("unsafe_metadata_url")
        declarations = {}
        singular = {"object_classes": "object_class", "connection_fields": "connection_field",
                    "facts": "fact", "relationship_classes": "relationship_class", "discovery_scopes": "scope"}
        for name, label in singular.items():
            rows = manifest.get(name, [])
            declarations[name] = {row["key"]: row for row in rows}
            if len(declarations[name]) != len(rows):
                raise ContractError("duplicate_" + label)
        dependencies = manifest["implementation"]["dependencies"]
        if len({(row["kind"], row["name"]) for row in dependencies}) != len(dependencies):
            raise ContractError("duplicate_dependency")
        fields = declarations["connection_fields"]
        for field in fields.values():
            condition = field.get("visible_when")
            if condition:
                control = fields.get(condition["field"])
                if (not control or control["secret"] or control is field or control.get("visible_when")
                        or "options" in control and condition["equals"] not in control["options"]):
                    raise ContractError("invalid_field_visibility")
            if field["type"] == "enum" and "default" in field and field["default"] not in field["options"]:
                raise ContractError("invalid_field_default")
            bounds = field.get("validation", {})
            if any(bounds[lo] > bounds[hi] for lo, hi in [("min_length", "max_length"), ("minimum", "maximum")]
                   if lo in bounds and hi in bounds):
                raise ContractError("invalid_field_bounds")
        classes = declarations["object_classes"]
        canonical = {"status", "name", "hostname", "asset_type", "vlan_id", "cidr", "gateway", "ip_address", "mac_address"}
        for fact in manifest.get("facts", []):
            namespace, suffix = fact["key"].split(".", 1)
            if (suffix in canonical or not set(fact["object_classes"]) <= classes.keys()
                    or any(key.split(".", 1)[0] != namespace for key in fact["object_classes"])):
                raise ContractError("invalid_fact_declaration")
        for relationship in manifest.get("relationship_classes", []):
            for side in ["source_object_classes", "target_object_classes"]:
                if (not set(relationship[side]) <= classes.keys()
                        or any(classes[key]["kind"] != "asset" for key in relationship[side])):
                    raise ContractError("invalid_relationship_class")
        for scope in manifest.get("discovery_scopes", []):
            if not set(scope["object_classes"]) <= classes.keys() or scope["required"] and not scope["default_enabled"]:
                raise ContractError("invalid_scope")
            if any(not set(row["default_values"]) <= set(row["allowed_values"]) for row in scope.get("filters", [])):
                raise ContractError("invalid_scope_filter")
        if manifest["publisher"]["id"] != manifest["distribution"]["provenance"]["publisher_id"]:
            raise ContractError("publisher_mismatch")
    except ContractError:
        raise
    except (ValidationError, KeyError, TypeError, ValueError, RecursionError):
        raise ContractError("invalid_manifest") from None
    return manifest
