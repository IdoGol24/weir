"""Credential inventory: which credentials exist, where, by name only.

Four sources (docs/inventory.md): the versioned list of standard credential
locations under the home directory, the project tree (imported gitleaks or
trufflehog results plus Weir's catalog), the agent's launch environment with
the shell startup files that re-export into it, and the approved map
<project>/.weir/reach.yml.

Values never leave the process. `take_inventory` returns a value-free report
and a store of keyed fingerprints plus offsets; it returns no values.
"""

from weir.inventory._types import (
    INVENTORY_SCHEMA,
    STORE_SCHEMA,
    Counts,
    Credential,
    EnvSource,
    EnvVarName,
    GitIgnoredFile,
    Inputs,
    Inventory,
    Location,
    LocationKind,
    NotScanned,
    NotScannedReason,
    Reason,
    Route,
    RouteStatus,
    Source,
    Store,
    StoredRecord,
    ValueState,
    inventory_json_schema,
    store_json_schema,
)
from weir.inventory.core import (
    InventoryInputError,
    InventoryInputs,
    InventoryResult,
    default_key_path,
    encode_report,
    encode_store,
    take_inventory,
)
from weir.inventory.fingerprint import FINGERPRINT_VERSION, FingerprintKeyError
from weir.inventory.locations import LOCATION_LIST_VERSION

__all__ = [
    "FINGERPRINT_VERSION",
    "INVENTORY_SCHEMA",
    "LOCATION_LIST_VERSION",
    "STORE_SCHEMA",
    "Counts",
    "Credential",
    "EnvSource",
    "EnvVarName",
    "FingerprintKeyError",
    "GitIgnoredFile",
    "Inputs",
    "Inventory",
    "InventoryInputError",
    "InventoryInputs",
    "InventoryResult",
    "Location",
    "LocationKind",
    "NotScanned",
    "NotScannedReason",
    "Reason",
    "Route",
    "RouteStatus",
    "Source",
    "Store",
    "StoredRecord",
    "ValueState",
    "default_key_path",
    "encode_report",
    "encode_store",
    "inventory_json_schema",
    "store_json_schema",
    "take_inventory",
]
