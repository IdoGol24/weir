# Ralis
# global agent instructions

- These rules bind human and agent contributors alike.
- Never use the em dash "—". Use plain dash "-" instead
- When writing commit messages, NEVER auto-add your agent name as co-author
- Never modify files that are marked as auto-generated, or committed fixtures.
  Regenerate them from their source instead. CHANGELOG.md is the exception:
  there is no generator, so it is hand-maintained, and a release that changes
  behaviour adds its entry in the same commit range.
- When making technical decisions, do not give much weight to development cost.
  Instead, prefer quality, simplicity, robustness, scalability, and long term maintainability.
- For one-off or infrequent operational work, start with the simplest direct end-to-end path. Do not build wrappers, control planes, policy layers, custom verifiers, or automation unless the direct path exposes a concrete blocker or repeated need that justifies the added machinery.
- When doing bug fixes, always start with reproducing the bug in an E2E setting as closely aligned with how an end user would experience it as possible.
  This makes sure you find the real problem so your fix will actually solve it.
- **Every test that pins a committed fixture must DERIVE its expectation from the
  artifact, never restate a literal, and must be demonstrated to fail under at least
  one source mutation.** A test that asserts the same constant the code sets is not a
  test, it is a copy - it passes for exactly as long as the code and the fixture are
  wrong together. This rule is not theoretical: the version-diff corpus shipped a
  baseline claiming `observations: []` while an uncataloged tool sat on the tainted
  path of every single fixture. All tests were green and all bytes were stable; only
  running the real taint engine against the committed bytes exposed it. Derive from
  the artifact (emit the trace, run the pipeline, compare), then break the source on
  purpose and watch the test fail before you trust it.
- When end-to-end testing a product, be picky about the UI you see and be obsessed with pixel perfection.
  If something clearly looks off, even if it is not directly related to what you are doing, try to get it fixed along the way.
- Apply that same high standard to engineering excellence: lint, test failures, and test flakiness.
  If you see one, even if it is not caused by what you are working on right now, still get it fixed.

## Corpora land with or after the contract that judges them

A fixture is a claim. The thing that judges it - spec text, a validator, or the
consumer it exercises - is that claim's test. A corpus committed before its
judging contract exists is a set of expectations nothing can falsify: it
freezes, work builds on it, and its errors surface only when the contract
finally lands, at which point the fixtures are load-bearing and expensive to
move.

Rule: before authoring fixtures, name the contract that judges them. If it
exists, cite it and derive expectations from it. If it does not, either write
the contract first or defer the corpus - and record the deferral with a named
landing site: the milestone whose first mandated action writes that contract.

Worked example: M3 deferred the corrupt OTLP corpus to M4 because the
reject-vs-degrade line is the adapter's contract to define and no text drew it
yet. Authoring those fixtures in M3 would have committed expectations no code
or spec could validate - the same shape as the diffspec observations lie,
which every test passed and only a real engine run caught.

Siblings: the derived-tests rule says HOW a fixture is validated (derive from
the artifact, prove by mutation). The producer-assertion rule says WHO may
assert (telemetry meta-claims are input, never trusted). This rule says WHEN a
fixture may exist at all.
