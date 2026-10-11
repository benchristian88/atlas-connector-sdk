# SPDX-License-Identifier: Apache-2.0
from copy import deepcopy
import hashlib
import importlib.util
import json
from pathlib import Path
import secrets

import pytest

from atlas_connector_sdk import __version__
from atlas_connector_sdk.contracts import ContractError, SCHEMA_DIGESTS, schema_bytes, strict_json, validate_manifest, validator, version_in_range
from atlas_connector_sdk.configuration import validate_configuration, source_compatibility

ROOT = Path(__file__).resolve().parents[1]


@pytest.mark.parametrize("name", SCHEMA_DIGESTS)
def test_canonical_schema_identity_bytes_and_metaschema(name):
    assert hashlib.sha256(schema_bytes(name)).hexdigest() == SCHEMA_DIGESTS[name]
    assert validator(name)


def test_v11_derivation_cannot_drift():
    spec = importlib.util.spec_from_file_location("evolution", ROOT / "tools/evolve_manifest.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    assert module.evolve(json.loads(schema_bytes("connector-manifest-v1"))) == json.loads(schema_bytes("connector-manifest-v1.1"))
    assert __version__ == "1.1.0"


@pytest.mark.parametrize("text", ['{"a":1,"a":2}', '{"a":NaN}', '{"a":1e999}'])
def test_ambiguous_json_is_rejected(text):
    with pytest.raises(ContractError):
        strict_json(text)


def test_semver_order_and_bounds():
    bounds = {"minimum": "1.1.0", "exclusive_maximum": "2.0.0"}
    assert version_in_range("1.1.0+local", bounds)
    assert not version_in_range("1.1.0-rc.1", bounds)
    assert not version_in_range("2.0.0", bounds)


def test_write_only_configuration_and_conditional_bounds():
    manifest = {"connection_fields": [
        {"key": "endpoint", "type": "url", "secret": False, "required": True},
        {"key": "credential", "type": "secret", "secret": True, "required": True},
        {"key": "mode", "type": "enum", "secret": False, "required": True, "options": ["verify", "pin"], "default": "verify"},
        {"key": "pin", "type": "fingerprint", "secret": False, "required": True, "visible_when": {"field": "mode", "equals": "pin"}},
    ]}
    value = secrets.token_urlsafe(24)
    config = {"endpoint": "https://192.168.1.2:8006"}
    result = validate_configuration(manifest, config, {"credential": value})
    assert value not in json.dumps(result)
    assert validate_configuration(manifest, config, configured_fields=["credential"]) == result
    for change in [{"credential": value}, {"mode": "other"}, {"endpoint": "file:///tmp/x"}, {"endpoint": "https://u:p@example.test"}, {"pin": "hidden"}]:
        with pytest.raises(ContractError):
            validate_configuration(manifest, {**config, **change}, {"credential": value})
    with pytest.raises(ContractError):
        validate_configuration(manifest, config, {})


def test_unqualified_versions_are_never_supported():
    manifest = {"source_versions": {"qualification": "unqualified", "qualified_versions": [], "known_incompatible": []}}
    assert source_compatibility(manifest, "8.4") == "untested"
    assert source_compatibility(manifest, None) == "unknown"


def probe_manifest():
    bounds = {"minimum": "1.1.0", "exclusive_maximum": "2.0.0"}
    return {"manifest_version": "1.1", "id": "fixture", "version": "0.1.0",
        "publisher": {"id": "atlas-official", "name": "Atlas"},
        "display": {"name": "Fixture", "description": "Contract fixture", "category": "virtualization", "documentation_uri": "https://example.test/manual"},
        "compatibility": {"sdk": bounds, "atlas": bounds, "aip": ["1.0"], "runtime": {"capability": "integration-runtime-v1", "baseline": bounds}},
        "source_versions": {"qualification": "unqualified", "qualified_versions": [], "known_incompatible": [], "newer_untested_policy": "allow_with_warning"},
        "capabilities": {"test_connection": True, "discover": False, "scheduling": False, "complete_snapshot": False},
        "connection_fields": [{"key": "endpoint", "type": "url", "label": "Endpoint", "required": True, "secret": False}],
        "implementation": {"runtime": "ansible", "entry_points": {"test_connection": "test_connection"}, "dependencies": []},
        "licensing": {"licence": "Apache-2.0", "notices": ["NOTICE"], "sbom": {"format": "SPDX", "path": "sbom.spdx.json"}},
        "distribution": {"bundle_digest": "sha256:" + "a" * 64, "asset_uri": "https://example.test/bundle.tar.gz",
            "provenance": {"method": "github-artifact-attestation-sigstore", "publisher_id": "atlas-official", "repository": "atlas-example/fixtures", "workflow": ".github/workflows/release.yml", "source_commit": "0" * 40, "evidence_uri": "https://example.test/attestation"}}}


def test_probe_only_manifest_v11_is_truthful_and_does_not_relax_v10():
    manifest = probe_manifest()
    validate_manifest(manifest)
    for mutate in [lambda m: m["implementation"]["entry_points"].update(discover="discover"),
                   lambda m: m["capabilities"].update(scheduling=True),
                   lambda m: m["capabilities"].update(discover="read_only"),
                   lambda m: m.update(manifest_version="1.0")]:
        bad = deepcopy(manifest)
        mutate(bad)
        with pytest.raises(ContractError):
            validate_manifest(bad)


@pytest.mark.parametrize("url", ["https://user:password@example.test", "file:///tmp/x", "https://example.test:444"])
def test_metadata_urls_and_format_are_checked(url):
    manifest = probe_manifest()
    manifest["display"]["documentation_uri"] = url
    with pytest.raises(ContractError):
        validate_manifest(manifest)
