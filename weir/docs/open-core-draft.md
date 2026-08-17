# Open-core boundary (DRAFT - not published, awaiting owner sign-off)

Status: draft for owner approval. This wording is a business decision; it
ships in the README only after the owner signs it. Do not link this file
from public-facing docs until then.

---

## Proposed section text

### What is open, permanently

The engine is Apache-2.0 and stays that way: the trace schema, the OTel
adapter and every future dialect row, the session graph, the taint and
evaluation engines, the gauge and its capability ladder, the reporters,
the paired trace generator, and the teaching rules. If it is required to
ingest your telemetry, measure what it can prove, or run a scan against
open rules, it is in the open engine - forever. The loader enforces
authenticity only, never entitlement: there is no license check inside
evaluation, no feature gate in the analysis path, and no telemetry
phoning home (the no-network guarantee is a test).

### Where the commercial layer will live

The commercial layer is content and services around the open engine, not
capability withheld from it: professionally maintained, signed rule
bundles with fixtures and provenance; the feed that keeps them current;
and support. Signed bundles are verified freely by the open engine -
signing is how you know who authored a rule, not a lock on running it.

---

## Notes for the owner (not part of the published text)

- The "authenticity, never entitlement" line restates the master spec's
  G10 no-DRM constitution; the published wording commits to it publicly.
- The bundle/feed framing matches the C2/C3 design (verify-before-merge,
  Sigstore) already in the M5 backlog; nothing here promises a date.
- Undecided and deliberately not mentioned: pricing, hosted offerings,
  and whether the future diff/baseline gate is open (current backlog
  treats it as open engine work; if that changes, this note must change
  BEFORE the README section ships).
