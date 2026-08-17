# Security policy

## Reporting

Report suspected vulnerabilities privately - do not open a public issue.
Use GitHub's private vulnerability reporting on this repository if
available, or email idogol24@gmail.com. You should hear back within a few
days; there is no bounty program.

## What counts

Weir analyzes attacker-influenced content by design (tool results and
message payloads are the tainted zone in its own threat model). The design
intent, enforced by tests, is that crafted content can at worst add
visible, low-confidence noise to the session graph. In scope, and
especially wanted:

- crafted trace content that silently rewires a witness path, suppresses
  or upgrades a finding, or influences join evidence above the
  content-mined tier;
- inputs that crash `weir gauge`/`weir scan` or make them exit anything
  other than 0, 1, or 2 (the reject-vs-degrade contract says malformed
  telemetry degrades with a named reason, never crashes);
- any path that leaks captured payload content (for example matched
  secrets) into outputs that redact it today.

Determinism violations (same input, different output) are bugs and may be
security-relevant; report them too.

## Supported versions

Pre-1.0: only the latest release is supported.
