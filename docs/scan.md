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
key pattern it finds sitting in a span, with no flow needed: OpenAI,
Anthropic, AWS, GitHub and Google API keys, Google OAuth access tokens
(`ya29.`), refresh tokens (`1//`, a digit, then 39 to 511 characters of
`A-Z`, `a-z`, `0-9`, `_` or `-`) and client secrets (`GOCSPX-`), the token
in an `Authorization: Bearer` header (also URL-encoded, as in
`authorization=Bearer%20...` or a whole encoded header line, judged as
the decoded token, and as the
`authorization` entry of a header map recorded as one attribute), and a
field whose name says it holds a credential (`api_key=...`,
`"password": "..."`, `"api_key": ["..."]`), including inside JSON that is
itself escaped in a string. A JSON-quoted value runs to its closing quote,
spaces included, and an array value, nested or not, is judged by its first
string item of 8 or more characters, after up to three leading `null`,
`None`, number or shorter string items. A placeholder first item therefore hides a
real value after it (`["REDACTED", "..."]` is not found). Under the key
`token` alone the value counts only when it has both a letter and a digit of
its own (an escape sequence such as `\n` or `\u0041` counts as neither), so
a logprobs `"token": "Certainly"` is not one, in any language. A key-name match has no shape to check, so it goes to
the review queue rather than failing the scan.

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
  over every fixture in the corpus. A span name, span id or attribute key
  that holds a value the scan found, eligible or in the review queue, or
  any 6 characters in a row of one, is printed as `[withheld]`, by the same
  rule the canary judge uses ([canary.md](canary.md)). Counts and exit
  codes are those of the names as found.
- **Nothing phoning home.** The analysis path opens no sockets, and the
  whole test suite runs with socket creation blocked
  ([tests/_harness/g3.py](../tests/_harness/g3.py)).

## Limits

- The flow scan needs content capture switched on in your instrumentation;
  `weir gauge` tells you whether it is.
