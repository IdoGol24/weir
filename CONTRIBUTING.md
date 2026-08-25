# Contributing

Thanks for looking. This is an early project; the most useful contributions
right now are bug reports against real traces and dialect coverage.

## Getting set up

    uv sync --group dev
    uv run pytest -q
    uv run ruff check .
    uv run pyright
    uv run lint-imports

All five must pass before a PR. CI runs the same five on Linux and Windows.

## How the pieces fit

- `packages/weir/src/weir/adapters/otel/` turns an OTLP export into weir's
  internal trace. Ingestion is reject-narrow: only not-telemetry is refused,
  and every real malformation degrades under a named contract row
  ([docs/contract.md](docs/contract.md), generated from code).
- `packages/weir/src/weir/catalog/` names the sensitive data classes and the
  outbound sinks. The catalog itself is `catalog/bundled/catalog.json`.
- `packages/weir/src/weir/rules_commons/bundled/` holds the rules. A rule is
  a JSON file naming a source class, a sink and a propagation mode.
- `packages/weir-tracegen/` generates the synthetic fixtures. **They are never
  hand-written**; CI regenerates them from seeds and fails on any diff.
- The one deliberate exception is `fixtures/foreign/`: a frozen capture from a
  real agent through real OTel instrumentation, with recorded provenance. It is
  pinned rather than regenerated, because weir not having written it is the
  entire point. It is byte-drift-tested like everything else.

## Two rules that are not negotiable

1. **A test that pins a committed fixture must derive its expectation from
   the artifact, never restate a literal, and must be shown to fail under at
   least one source mutation.** A test asserting the same constant the code
   sets is a copy, not a test.
2. **A corpus lands with or after the contract that judges it.** If the thing
   that would judge your fixtures does not exist yet, the fixtures wait.

Both rules exist because this repo shipped a corpus that violated them and
only caught it by running the real engine against the committed bytes.

## Reporting a trace weir handles badly

The most valuable bug report is a real export weir mis-reads. Redact it, note
which instrumentation produced it, and open an issue with the `weir gauge`
output. Ingestion bugs are the ones that block everyone.

## Adding a data type

The catalog and the rules are data. Adding a source class is a JSON edit, and
`github_token` was added exactly that way as the first type contributed
through this path rather than authored alongside the engine.

A source class entry looks like this, in
`packages/weir/src/weir/catalog/bundled/catalog.json`:

```json
{
  "name": "github_token",
  "content_pattern": "\\bghp_[A-Za-z0-9]+\\b",
  "eligibility": {"pattern": "ghp_[A-Za-z0-9]{36}"}
}
```

**`content_pattern` must be strictly looser than `eligibility.pattern`.**
This is the one trap worth stating up front. Copying the type's shape into
both fields is the obvious move and it is wrong: the labeler records the
whole match, so anything the label pattern finds would already satisfy an
identical eligibility pattern. Eligibility silently becomes a tautology and
your near-miss fixture becomes impossible to write. The loose pattern finds
candidates; the strict one judges them.

Use `eligibility.pattern` unless your type has a real checksum. IBAN's mod-97
and PAN's Luhn do, and those need a validator function in
`structure_classes.py`. Most types do not.

The matching rule is also just data. This is the whole shipped file:

<!-- verify-file: packages/weir/src/weir/rules_commons/bundled/github-token-to-outbound-sink.json -->
```json
{
  "id": "github-token-to-outbound-sink",
  "version": "1.0.0",
  "stage": "active",
  "description": "Untrusted content reaches an outbound sink verbatim, carrying a GitHub personal access token (R5.9).",
  "source_class": "github_token",
  "sink_tool_name": "send_email",
  "mode": "verbatim"
}
```

Then two fixtures, both required: one where the value reaches a sink and the
finding fires, and **one near-miss that clears `content_pattern`, fails
eligibility, and must not fire**. `content_pattern` is deliberately loose, so
without the near-miss nothing proves eligibility discriminates rather than
waving everything through.

### What is not yet smooth, stated plainly

The catalog entry and the rule are genuinely data. **The fixtures are not.**
Walking `github_token` through end to end turned up friction worth knowing
before you start:

- `weir_tracegen`'s scenario library is Python. `SCENARIOS` is a dict of
  builder functions with planted values as module constants, so there is no
  data-driven way to say "plant value V of class C". `ScenarioSpec` is a
  msgspec struct and would round-trip through JSON with almost no new code,
  but nothing loads one yet.
- Adding a catalog entry changes the catalog digest, which stales the
  diffspec baselines that embed it. Regenerating them needs the full dev
  environment.
- Three false-positive classes need different answers, and only the first is
  covered by the required near-miss: a structural near-miss (right shape,
  fails validation); a structurally valid but non-secret value (weir's own
  demo secret is the well-known German test IBAN, and 4111111111111111 passes
  Luhn); and a legitimate flow, where the value is real and the flow is
  authorized. **Structure cannot help with the third at all**, so weir
  over-reports on any type whose flow is sometimes legitimate.

None of this blocks a contribution, but it means "adding a data type is a
JSON edit" is true for the catalog and the rule and not yet true for the
fixtures. Open an issue and we will work through it, and what breaks becomes
the next improvement to this guide.

## Security

Do not open a public issue for a security finding. See
[SECURITY.md](SECURITY.md). If you can make attacker-controlled content do
more than add visible low-confidence noise, that is a security bug.
