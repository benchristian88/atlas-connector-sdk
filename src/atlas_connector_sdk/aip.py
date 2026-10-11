# SPDX-License-Identifier: Apache-2.0
"""Deterministic contract fixture checks; no ingestion or persistence service."""
import hashlib
import ipaddress
import json

from .contracts import ContractError, validator


def body_hash(message):
    return hashlib.sha256(json.dumps(message, sort_keys=True, separators=(",", ":"),
                                     ensure_ascii=False, allow_nan=False).encode()).hexdigest()


def validate_batch(message, manifest):
    from jsonschema.exceptions import ValidationError
    try:
        validator("aip-v1").validate(message)
        identity = {"id": manifest["id"], "version": manifest["version"],
                    "bundle_digest": manifest["distribution"]["bundle_digest"]}
        if message["connector"] != identity or manifest["capabilities"]["discover"] is False:
            raise ContractError("invalid_aip_binding")
        if message["message_type"] == "completion":
            return message
        classes = {row["key"]: row for row in manifest["object_classes"]}
        facts = {row["key"]: row for row in manifest["facts"]}
        relations = {row["key"]: row for row in manifest["relationship_classes"]}
        for domain, kind in [("assets", "asset"), ("networks", "network"), ("interfaces", "interface")]:
            if message[domain] and domain not in message["coverage"]["domains"]:
                raise ContractError("observation_outside_coverage")
            for row in message[domain]:
                declaration = classes.get(row["object_class"])
                if not declaration or declaration["kind"] != kind:
                    raise ContractError("invalid_object_class")
                if len({fact["key"] for fact in row["facts"]}) != len(row["facts"]):
                    raise ContractError("duplicate_entity_fact")
                for fact in row["facts"]:
                    declaration = facts.get(fact["key"])
                    if (not declaration or row["object_class"] not in declaration["object_classes"]
                            or any(fact[name] != declaration[name] for name in ["value_type", "class", "cardinality"])):
                        raise ContractError("invalid_fact")
                for name in ["ip_address", "gateway"]:
                    if name in row:
                        ipaddress.ip_address(row[name])
                if "cidr" in row:
                    ipaddress.ip_network(row["cidr"], strict=True)
        if message["relationships"] and "relationships" not in message["coverage"]["domains"]:
            raise ContractError("observation_outside_coverage")
        if any(row["relationship_class"] not in relations for row in message["relationships"]):
            raise ContractError("invalid_relationship_class")
    except ContractError:
        raise
    except (ValidationError, KeyError, ValueError, TypeError, RecursionError):
        raise ContractError("invalid_aip") from None
    return message


def validate_example_stream(messages, manifest):
    completions = [row for row in messages if row.get("message_type") == "completion"]
    if len(completions) != 1:
        raise ContractError("invalid_completion_count")
    completion = completions[0]
    batches = {}
    for message in messages:
        validate_batch(message, manifest)
        if any(message.get(name) != completion.get(name) for name in ["run_id", "integration_id", "connector", "coverage", "source"]):
            raise ContractError("invalid_stream_binding")
        if message["message_type"] == "observations":
            sequence = message["batch"]["sequence"]
            if sequence in batches and body_hash(batches[sequence]) != body_hash(message):
                raise ContractError("conflicting_receipt")
            batches[sequence] = message
    if set(batches) != set(range(1, completion["last_sequence"] + 1)):
        raise ContractError("incomplete_receipts")
    if completion["status"] == "completed" and not batches:
        raise ContractError("missing_observation_batch")
    incomplete = {"permission_limited", "source_unavailable", "authentication_failed", "tls_trust_required",
                  "source_incompatible", "invalid_source_record", "timeout"}
    if completion["completeness"] == "complete" and (
            not manifest["capabilities"]["complete_snapshot"]
            or any(warning["code"] in incomplete for message in messages for warning in message.get("warnings", []))):
        raise ContractError("incomplete_coverage")
    domains = {name: [row for index in sorted(batches) for row in batches[index][name]]
               for name in ["assets", "networks", "interfaces", "relationships"]}
    for rows in domains.values():
        if len({row["external_id"] for row in rows}) != len(rows):
            raise ContractError("duplicate_source_identity")
    assets = {row["external_id"]: row for row in domains["assets"]}
    networks = {row["external_id"] for row in domains["networks"]}
    if any(row["asset_external_id"] not in assets or "network_external_id" in row and row["network_external_id"] not in networks
           for row in domains["interfaces"]):
        raise ContractError("invalid_interface_binding")
    declarations = {row["key"]: row for row in manifest["relationship_classes"]}
    for row in domains["relationships"]:
        declaration = declarations[row["relationship_class"]]
        for side in ["source", "target"]:
            endpoint = assets.get(row[side]["external_id"])
            if endpoint is None or endpoint["object_class"] not in declaration[side + "_object_classes"]:
                raise ContractError("invalid_relationship_binding")
    return domains
