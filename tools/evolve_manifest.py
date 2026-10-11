# SPDX-License-Identifier: Apache-2.0
"""Deterministically derive the additive 1.1 schema from immutable Manifest 1.0."""
from copy import deepcopy
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def evolve(original):
    schema = deepcopy(original)
    schema["$id"] = "urn:atlas-connector-sdk:manifest:1.1"
    schema["title"] = "Connector Manifest v1.1"
    props = schema["properties"]
    props["manifest_version"] = {"const": "1.1"}
    props["source_versions"]["properties"]["qualification"]["enum"] += ["unqualified", "untested"]
    props["capabilities"]["properties"]["discover"] = {"enum": [False, "read_only"]}
    entry = props["implementation"]["properties"]["entry_points"]
    entry["required"] = ["test_connection"]
    discovery = ["discovery_scopes", "object_classes", "relationship_classes", "facts"]
    schema["required"] = [name for name in schema["required"] if name not in discovery]
    schema["allOf"] = [{
        "if": {"properties": {"capabilities": {"properties": {"discover": {"const": False}}}}},
        "then": {"properties": {
            "capabilities": {"properties": {"scheduling": {"const": False}, "complete_snapshot": {"const": False}}},
            "implementation": {"properties": {"entry_points": {"not": {"required": ["discover"]}}}},
            **{name: {"maxItems": 0, "minItems": 0} for name in discovery},
        }},
        "else": {"required": discovery, "properties": {
            "implementation": {"properties": {"entry_points": {"required": ["discover"]}}},
        }},
    }]
    # Discovery arrays are optional/empty only for probe-only packages.
    for name in discovery:
        props[name]["minItems"] = 0
    schema["allOf"][0]["else"]["properties"].update({
        name: {"minItems": original["properties"][name]["minItems"]} for name in discovery
    })
    return schema


if __name__ == "__main__":
    directory = ROOT / "src/atlas_connector_sdk/schemas"
    schema = evolve(json.loads((directory / "connector-manifest-v1.schema.json").read_bytes()))
    (directory / "connector-manifest-v1.1.schema.json").write_text(json.dumps(schema, indent=2) + "\n")
