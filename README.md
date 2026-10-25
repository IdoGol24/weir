# Weir

**Leak tests for AI agents.** Plant fake credentials where your real ones live, run your agent, and find every place it exposed them: its telemetry, the model it calls, or any other service.

[![CI](https://github.com/IdoGol24/weir/actions/workflows/ci.yml/badge.svg)](https://github.com/IdoGol24/weir/actions/workflows/ci.yml) [![PyPI](https://img.shields.io/pypi/v/weir-scan)](https://pypi.org/project/weir-scan/) [![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](https://github.com/IdoGol24/weir/blob/main/LICENSE)

![Weir plants fake keys in your agent, lets its telemetry flow, and checks every span, log and metric for those exact values: leak, clean or incomplete.](https://raw.githubusercontent.com/IdoGol24/weir/main/docs/assets/weir-flow.svg)

## Try it in 10 seconds

```sh
pip install weir-scan
weir canary judge --sample
```

![Terminal recording: weir canary judge --sample prints a LEAK line naming the planted fake key and the span it reached, then "result: leak", and exits 1.](https://raw.githubusercontent.com/IdoGol24/weir/main/docs/assets/demo.svg)

## Two ways to use it

### 1. Test your agent, in CI or on your laptop

`weir-run` plants a unique fake key wherever a real one would live, runs your agent's own flows against a local fake model, and captures everything the agent sends out. `weir canary judge` then searches all of it for those exact values.

```sh
pip install weir-scan weir-run
weir-run run --config canary.toml
```

```toml
[[placement]]
id = "env.OPENAI_API_KEY"
kind = "env"
shape = "openai"
required = true
provider = "model"     # where this key is allowed to go

[[flow]]
id = "quickstart"
command = ["{python}", "examples/quickstart.py"]
```

In a pull request, one step runs it and posts the verdict as a comment:

```yaml
- uses: IdoGol24/weir@<ref>
```

Config, pytest fixture and the full workflow: [weir-run README](https://github.com/IdoGol24/weir/tree/main/packages/weir-run) · [action README](https://github.com/IdoGol24/weir/tree/main/action).

### 2. Watch your own Claude Code sessions

A status-line segment counts how many of your real credentials entered the session's context, and how many were sent out in a tool call. `/weir` explains each one: where it came from, the turn that moved it, where it sits now, and what to do. It never shows a value.

![The weir segment beside an existing status line: a green check and "nothing exposed", then a warning sign with "2 in context" in amber and "1 sent" in red.](https://raw.githubusercontent.com/IdoGol24/weir/main/docs/assets/statusline-states.svg)

```sh
uv tool install weir-scan     # or: pipx install weir-scan
weir statusline setup         # shows the change, applies it only when you type yes
```

`weir statusline undo` removes it. Linux and macOS. Details: [docs/statusline.md](https://github.com/IdoGol24/weir/blob/main/docs/statusline.md).

## Why it's different

- **It doesn't guess.** It looks for the exact values it planted, raw or encoded, so a hit is a real leak.
- **It checks every way out:** spans, logs, metrics, console output, prompts sent to the model, and requests to any other service. On Linux, where unprivileged user namespaces are allowed, the agent runs with no outside network, so a direct connection is caught too.
- **No false all-clear.** If something you marked required wasn't exercised, the result is "incomplete", never "clean". Exit codes: 0 clean, 1 leak, 2 unusable input, 3 incomplete.
- **Offline and deterministic.** No AI model decides anything, and Weir itself sends nothing anywhere. Tests enforce both.

**Found with Weir:** [GHSA-j7qq-vr8c-xvw3](https://github.com/mlflow/mlflow/security/advisories/GHSA-j7qq-vr8c-xvw3), an MLflow advisory, fixed in 3.17.0.

## Limits

- It finds whole values only, not hashed, split or truncated ones.
- It sees only what the agent sends while the test runs.
- Network isolation is Linux-only and needs unprivileged user namespaces. Elsewhere the report says the network wasn't isolated.
- The fake model speaks the OpenAI-compatible and Anthropic Messages APIs.

The full list is in [docs/canary.md](https://github.com/IdoGol24/weir/blob/main/docs/canary.md).

## Also in the box

- **`weir scan`:** follows sensitive data through traces you already have, for example from untrusted tool output to an outgoing email.
- **`weir inventory`:** lists the credentials an agent could reach, by name only.
- **`weir audit`:** checks your real credentials against saved agent sessions, offline.

## FAQ

**Does it need my real keys?** No. Tests use fake values only. For the status line, Weir stores only keyed fingerprints of your real keys, never the keys themselves.

**How is it different from gitleaks or trufflehog?** They find strings that look like secrets in your code. Weir proves whether a specific value actually left through your agent. Use both.

**Does it send anything anywhere?** No. The fake model listens on 127.0.0.1 only and forwards nothing, and the scanner opens no network connections. Tests enforce both.

## License

Apache-2.0, all of it, permanently. Nothing held back, nothing gated, nothing phoning home.

## Why "weir"

<p align="center">
  <img src="https://raw.githubusercontent.com/IdoGol24/weir/main/docs/assets/weir.jpg" alt="A weir: a low dam across a river, with water flowing evenly over its crest" width="560">
  <br>
  <em>A weir is a low dam that measures a river's flow. The water keeps moving; the measurement happens anyway.</em>
  <br>
  <sub>Damhead Weir, Water of Leith. Photo by 501ghost, Wikimedia Commons, CC0.</sub>
</p>
