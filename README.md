# Weir

**Leak tests for AI agents.**

![Weir plants fake keys in your agent, lets its telemetry flow, and checks every span, log and metric for those exact values: leak, clean or incomplete.](https://raw.githubusercontent.com/IdoGol24/weir/main/docs/assets/weir-flow.svg)

Plant fake credentials where your real ones live, run your agent, and find out exactly where they ended up, before a real key does.

```sh
pip install weir-scan
weir canary judge --sample
```

[![CI](https://github.com/IdoGol24/weir/actions/workflows/ci.yml/badge.svg)](https://github.com/IdoGol24/weir/actions/workflows/ci.yml) [![PyPI](https://img.shields.io/pypi/v/weir-scan)](https://pypi.org/project/weir-scan/) [![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](https://github.com/IdoGol24/weir/blob/main/LICENSE)

## How it works

Weir is two packages that work together, in CI or on your laptop:

- **weir-run is the test rig.** It plants a unique fake credential wherever a real one would live, runs your agent's own flows against a fake model on 127.0.0.1, and captures everything the agent exports.
- **weir-scan is the inspector.** It reads that capture and gives the verdict: leak, clean or incomplete. It also works on its own, on traces you already have.

```sh
pip install weir-scan weir-run
```

## Who it's for

- **Teams building agents:** run it in CI on every dependency update. A framework or tracing upgrade that starts writing keys into telemetry fails the build, like a regression test for leaks.
- **Framework and tracing maintainers:** run it before each release, so the next advisory isn't about you.

## Why it's different

- **It doesn't guess.** It looks for the exact values it planted, so a hit is a real leak, and a key is found even when it doesn't look like a key, raw or encoded.
- **Offline and deterministic.** No AI model decides anything, and Weir sends nothing anywhere. The scanner opens no sockets and starts no processes, and CI enforces that.
- **No false all-clear.** If a run didn't exercise something you marked required, Weir says "incomplete", not "clean", and shows exactly what it checked. Exit codes: 0 clean, 1 leak, 2 unusable input, 3 incomplete.

## Proof

Found with Weir: [GHSA-j7qq-vr8c-xvw3](https://github.com/mlflow/mlflow/security/advisories/GHSA-j7qq-vr8c-xvw3), an MLflow advisory, fixed in MLflow 3.17.0.

## Try it on your own agent

The sample is a bundled fake ledger and capture with one planted value in a span attribute, so the check exits 1 and prints its leak report. It names the placement and the span, never the value:

<!-- verify: canary judge --sample -->
```text
LEAK env.SAMPLE_SERVICE_KEY file=canary-sample/otlp.jsonl:1 signal=traces span="call_service" at=attributes.app.client.config form=raw
coverage: 2 placements (1 leaked, 1 exercised, 0 not exercised, 1 required), 1 flows (1 ok), 1 files, 3 spans, 0 log records, 0 metric data points, 29 strings, 1347 bytes swept
result: leak
```

On your own agent:

```sh
weir-run run --config canary.toml
```

The config names where your credentials live and which flows to run. The [weir-run README](https://github.com/IdoGol24/weir/tree/main/packages/weir-run) covers the config, the fake model, a `canary_check` pytest fixture and a demo. The judge's contract, including every encoding it matches, is [docs/canary.md](https://github.com/IdoGol24/weir/blob/main/docs/canary.md).

## Also included: the flow scan and `weir inventory` (experimental)

### The flow scan

`weir scan` reads the OpenTelemetry traces your agent already emits and fails the build when sensitive data travels to a place it should never reach, for example a bank account number from untrusted tool output that ends up in an outgoing email. It rebuilds the session step by step from the trace, follows the data, and prints the source, the destination and every step in between.

```sh
weir gauge your-export.jsonl   # or: weir gauge --sample
weir scan your-export.jsonl
```

Most exports cannot support this yet, because content capture ships off by default almost everywhere. `weir gauge` measures how much of your trace the scan can actually see, and names the exact setting to switch on, read from the instrumentation in your own trace. The scan also reports any provider key pattern it finds sitting in a span, with no flow needed.

Each check is a rule, and a rule is a short JSON file naming a source, a destination and a match mode ([bundled rules](https://github.com/IdoGol24/weir/tree/main/packages/weir/src/weir/rules_commons/bundled)). Rewording prompts or adding a step does not change the result. When the trace evidence is too weak to prove a flow, the finding stays in the report, marked as not proven and saying why, instead of quietly disappearing.

`weir scan` exits 0 when nothing fails, 1 on a finding and 2 on unusable input.

### `weir inventory` (experimental)

`weir inventory --home DIR` lists the credentials an agent could reach: standard credential files, project files (with imported gitleaks or trufflehog results), the launch environment and shell startup files, and the approved map `.weir/reach.yml`. It reports them by name, source and location only. It never prints, logs or stores a value; what it can store is a keyed fingerprint plus offsets ([contract](https://github.com/IdoGol24/weir/blob/main/docs/inventory.md)). Its output and JSON schema may change without notice.

## Why you can trust it

- **It searches for what it planted.** A hit is a planted value found in the capture, never a pattern guess, and the judge's output depends only on where values appear, never on what they are.
- **Nothing phoning home: a test, not a promise.** The analysis path opens no sockets. The whole test suite runs with socket creation blocked ([tests/_harness/g3.py](https://github.com/IdoGol24/weir/blob/main/tests/_harness/g3.py)), and [packages/weir/tests/test_canary_judge.py](https://github.com/IdoGol24/weir/blob/main/packages/weir/tests/test_canary_judge.py) fails if the judge opens a socket or starts a process.
- **Nothing Weir prints is a credential.** The judge names placements and locations, never a value or a fragment of one. No rendered weir output (text, gauge, HTML, ledger) contains a credential-shaped value; that is a test over every fixture in the corpus.
- **It reads real traces, not only ones we wrote.** The suite pins a frozen capture that no weir code ever touched ([provenance](https://github.com/IdoGol24/weir/blob/main/fixtures/foreign/PROVENANCE.md)). Malformed input is reported under one of a fixed list of named cases; it never guesses ([contract](https://github.com/IdoGol24/weir/blob/main/docs/contract.md)).
- **Attacker text cannot fake a flow.** The flow scan fails the build only on links between steps that the instrumentation itself records. A flow that rests on a link inferred from matching text is reported, but never fails the build. Getting past that is a security bug ([SECURITY.md](https://github.com/IdoGol24/weir/blob/main/SECURITY.md)).
- **Claims about other people's software are sourced and dated** ([REMEDIATION_SOURCES.md](https://github.com/IdoGol24/weir/blob/main/REMEDIATION_SOURCES.md)).

## FAQ

**Why not just use SecretStr or redact in the collector?**
Redaction is worth doing. Weir checks whether it worked: it searches the exported output for the exact planted values, whatever path they took to get there.

**How is this different from gitleaks or trufflehog?**
They find strings that look like secrets in code and files. Weir proves whether a value you planted reached your telemetry, in any of the encodings [docs/canary.md](https://github.com/IdoGol24/weir/blob/main/docs/canary.md#the-encoded-forms) lists. It does not replace them.

**Does it need my real keys?**
No. It uses fake values by design, and a real key should never be in a run.

**Does it send anything anywhere?**
No. The analysis opens no sockets, and a test enforces it. The rig's fake model listens on `127.0.0.1` only and refuses every proxied request to another host.

**Which frameworks?**
Any that can export OpenTelemetry spans to a file.

## Honest limits

A clean result is evidence about the flows that ran and the credentials planted, not a statement that the program is safe.

- It finds whole values only. A truncated, split or partly masked value, a hashed, encrypted or compressed one, and encodings beyond those [docs/canary.md](https://github.com/IdoGol24/weir/blob/main/docs/canary.md#the-encoded-forms) lists (URL-encoded base64, UTF-16, line-wrapped base64) are not matched.
- It sees only telemetry that reached the capture.
- This release plants environment variables, values passed in code, and OAuth tokens. Model APIs must be OpenAI-compatible.
- The rig does not sandbox the network. A client that ignores the proxy settings and has a hard-coded host can reach that host directly; run such flows in a container or network namespace with no route out.
- The flow scan needs content capture switched on in your instrumentation; `weir gauge` tells you whether it is.

## License

Apache-2.0, all of it, permanently. Nothing held back, nothing gated, nothing phoning home.

Install `weir-scan`; the import and the command are both `weir`.

## Why "weir"

<p align="center">
  <img src="https://raw.githubusercontent.com/IdoGol24/weir/main/docs/assets/weir.jpg" alt="A weir: a low dam across a river, with water flowing evenly over its crest" width="560">
  <br>
  <em>A weir is a low dam built across a river to regulate and measure its
  flow - the water keeps moving; the measurement happens anyway.</em>
  <br>
  <sub>Damhead Weir, Water of Leith. Photo by 501ghost, Wikimedia Commons, CC0.</sub>
</p>
