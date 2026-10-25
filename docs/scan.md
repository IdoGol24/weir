# weir scan: the flow scan

`weir scan` reads the OpenTelemetry traces your agent already emits and
fails the build when sensitive data travels to a place it should never
reach, for example a bank account number from untrusted tool output that
ends up in an outgoing email. It rebuilds the session step by step from the
trace, follows the data, and prints the source, the destination and every
step in between.

```sh
weir gauge your-export.jsonl   # or: weir gauge --sample
weir scan your-export.jsonl
```

Most exports cannot support this yet, because content capture ships off by
default almost everywhere. `weir gauge` measures how much of your trace the
scan can actually see, and names the exact setting to switch on, read from
the instrumentation in your own trace. The scan also reports any provider
key pattern it finds sitting in a span, with no flow needed.

Each check is a rule, and a rule is a short JSON file naming a source, a
destination and a match mode ([bundled
rules](../packages/weir/src/weir/rules_commons/bundled)). Rewording prompts
or adding a step does not change the result. When the trace evidence is too
weak to prove a flow, the finding stays in the report, marked as not proven
and saying why, instead of quietly disappearing.

`weir scan` exits 0 when nothing fails, 1 on a finding and 2 on unusable
input.

Install `weir-scan`; the import and the command are both `weir`.

## Which frameworks?

Any that can export OpenTelemetry spans to a file.

## Why you can trust it

- **It reads real traces, not only ones we wrote.** The suite pins a frozen
  capture that no weir code ever touched
  ([provenance](../fixtures/foreign/PROVENANCE.md)). Malformed input is
  reported under one of a fixed list of named cases; it never guesses
  ([contract](contract.md)).
- **Attacker text cannot fake a flow.** The flow scan fails the build only
  on links between steps that the instrumentation itself records. A flow
  that rests on a link inferred from matching text is reported, but never
  fails the build. Getting past that is a security bug
  ([SECURITY.md](../SECURITY.md)).
- **Claims about other people's software are sourced and dated**
  ([REMEDIATION_SOURCES.md](../REMEDIATION_SOURCES.md)).
- **Nothing Weir prints is a credential.** No rendered weir output (text,
  gauge, HTML, ledger) contains a credential-shaped value; that is a test
  over every fixture in the corpus.
- **Nothing phoning home.** The analysis path opens no sockets, and the
  whole test suite runs with socket creation blocked
  ([tests/_harness/g3.py](../tests/_harness/g3.py)).

## Limits

- The flow scan needs content capture switched on in your instrumentation;
  `weir gauge` tells you whether it is.
