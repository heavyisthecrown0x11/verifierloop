"""verifierloop-analysis — Python side of the Rust<->Python language boundary.

Rust owns orchestration and produces normalized-metric JSON artifacts under a
period directory. Python (this package) owns statistics / data processing /
anomaly scoring: it reads those artifacts and writes scores/diagnostics back as
JSON. See `contract`.

SCAFFOLDING: importable stubs only. No scoring logic is implemented.
"""

# Keep in lockstep with the Rust `contract` crate's CONTRACT_VERSION.
# TODO(contract): freeze at v1 when the schema lands.
CONTRACT_VERSION = 0

__all__ = ["contract", "scoring", "schemas"]
