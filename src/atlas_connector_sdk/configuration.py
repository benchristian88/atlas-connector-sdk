# SPDX-License-Identifier: Apache-2.0
"""Declarative field validation, shared by application and Connector consumers."""
import math
from urllib.parse import urlsplit

from .contracts import ContractError


def visible(field, config):
    condition = field.get("visible_when")
    return not condition or config.get(condition["field"]) == condition["equals"]


def validate_configuration(manifest, config, credentials=None, *, configured_fields=()):
    """Return safe normalized config; validate credential presence without reading it.

    Credentials, when provided, are a complete replacement, never a partial
    merge. Errors contain fixed codes, never submitted values.
    """
    if not isinstance(config, dict) or credentials is not None and not isinstance(credentials, dict):
        raise ContractError("invalid_configuration")
    fields = manifest["connection_fields"]
    safe_keys = {field["key"] for field in fields if not field["secret"]}
    secret_keys = {field["key"] for field in fields if field["secret"]}
    if not config.keys() <= safe_keys or credentials is not None and not credentials.keys() <= secret_keys:
        raise ContractError("unknown_configuration_field")
    normalized = {field["key"]: field["default"] for field in fields if not field["secret"] and "default" in field}
    normalized.update(config)
    present = set(credentials) if credentials is not None else set(configured_fields)
    for field in fields:
        key = field["key"]
        active = visible(field, normalized)
        supplied = key in present if field["secret"] else key in normalized
        if not active:
            if supplied:
                raise ContractError("hidden_configuration_field")
            continue
        if field["required"] and not supplied:
            raise ContractError("required_configuration_field")
        if not supplied or field["secret"] and credentials is None:
            continue
        value = credentials[key] if field["secret"] else normalized[key]
        kind = field["type"]
        if kind == "boolean":
            valid = type(value) is bool
        elif kind == "number":
            try:
                valid = type(value) in {int, float} and math.isfinite(value)
            except OverflowError:
                valid = False
        elif kind == "enum":
            valid = any(type(value) is type(option) and value == option for option in field["options"])
        else:
            valid = isinstance(value, str) and 0 < len(value) <= 2048 and not any(ord(char) < 32 for char in value)
        if not valid:
            raise ContractError("invalid_configuration_field")
        bounds = field.get("validation", {})
        if isinstance(value, str):
            if not bounds.get("min_length", 1) <= len(value) <= bounds.get("max_length", 2048):
                raise ContractError("invalid_configuration_field")
        elif type(value) in {int, float}:
            if value < bounds.get("minimum", -math.inf) or value > bounds.get("maximum", math.inf):
                raise ContractError("invalid_configuration_field")
        if kind == "url":
            try:
                endpoint = urlsplit(value)
                if (endpoint.scheme != "https" or not endpoint.hostname or endpoint.username is not None
                        or endpoint.password is not None or endpoint.query or endpoint.fragment
                        or endpoint.port == 0 or "\\" in value or any(char.isspace() for char in value)):
                    raise ValueError
            except ValueError:
                raise ContractError("unsafe_endpoint") from None
    return normalized


def source_compatibility(manifest, version):
    policy = manifest["source_versions"]
    if version is None:
        return "unknown"
    if any(row["version"] == version for row in policy["known_incompatible"]):
        return "known_incompatible"
    if policy["qualification"] == "qualified" and version in policy["qualified_versions"]:
        return "supported"
    return "untested"
