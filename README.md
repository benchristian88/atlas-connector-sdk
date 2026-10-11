# Atlas Connector SDK

Apache-2.0 canonical runtime-neutral AIP/Manifest contracts. The SDK owns the
schemas and validation helpers; it contains no Atlas database, domain, tenancy,
runtime, installation trust or Connector implementation.

Version **1.1.0** packages byte-identical AIP 1.0 and Manifest 1.0 schemas and the
additive Manifest 1.1 extension. Manifest 1.0 stays supported. Manifest 1.1 can
truthfully declare a verified Test Connection-only package (`discover: false`),
without a discovery entry point or declarations. Source qualification can be
`unqualified`/`untested`; `example` is never production activation authority.
Discovery packages retain the existing declarations and fixed entry points.

`validate_manifest` checks shape, formats and cross-declaration semantics.
`configuration.validate_configuration` separates secrets from safe config and
supports configured-field presence without retrieving plaintext.
`aip.validate_example_stream` checks deterministic fixtures, not ingestion.

Use Python 3.12+. Install the pinned backend declared in `pyproject.toml` and
`build==1.3.0`, then run:

```bash
python -m pytest -q
python tools/build.py
```

`tools/evolve_manifest.py` derives 1.1 from unchanged 1.0; the regression suite
rejects drift. Schema IDs and byte digests are pinned in `contracts.py`.
Wheel builds fix `SOURCE_DATE_EPOCH`; build twice and compare SHA-256 before
consumer staging. Atlas and atlas-connectors must consume the same exact wheel
with pinned version/hash, never a mutable Git branch or copied schema source.
The consumer wheel is a distribution artifact, not a second canonical source.
No package publication or remote provenance is claimed by a local build.
