# Open-core boundary

Status: signed by the owner, 2026-08-17. This is the published wording.

---

### What is open, permanently

The engine is Apache-2.0 and stays that way: the trace schema, the OTel
adapter and every future dialect row, the session graph, the taint and
evaluation engines, the gauge and its capability ladder, the reporters,
the paired trace generator, and the teaching rules. That includes the
future diff/baseline gate (`weir diff` / `weir baseline`): the
unit-test-for-agents promise is the open engine, permanently. If it is
required to ingest your telemetry, measure what it can prove, or run a
scan against open rules, it is in the open engine - forever. The loader
enforces authenticity only, never entitlement: there is no license check
inside evaluation, no feature gate in the analysis path, and no telemetry
phoning home: the analysis path opens no sockets (tested); fetching rule
bundles is a separate, explicit command.

### Where the commercial layer will live

The commercial layer is content and services around the open engine, not
capability withheld from it: professionally maintained, signed rule
bundles with fixtures and provenance; the feed that keeps them current;
and support. Signed bundles are verified freely by the open engine -
signing is how you know who authored a rule, not a lock on running it.
