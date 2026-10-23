# weir statusline: the Claude Code status-line segment and /weir report

> **Experimental.** `weir statusline` is experimental: its words, flags and
> files may change without notice.

> **The contract.** `weir statusline` (in `packages/weir/src/weir/statusline/`)
> implements this document, and this document is what its implementation
> and its tests are judged against. Where code and this text disagree, one
> of them is a bug.

`weir statusline` puts [`weir audit`](audit.md) where a person working with
Claude Code can see it: a short segment on Claude Code's status line that
counts how many of their own inventoried credentials entered the current
session's context and how many were sent out in a tool call, and a `/weir`
command that reports, per credential, where it came from, the turn and tool
call that moved it, where it now sits, and what to do.

It is display only, local and offline. It reads the session files Claude
Code names, with the keyed fingerprints of a
[`weir inventory --store`](inventory.md) run, and prints counts, names and
places. It never prints, caches or writes a credential value or any run of
6 characters of one. It changes no file of Claude Code's except through
`weir statusline setup`, which shows the exact change first and writes it
only after an explicit yes.

## The segment

```sh
weir statusline --inventory REPORT --store STORE --key KEY --cache DIR [--inner COMMAND] [--budget-ms N]
```

Claude Code runs this command (see [Setup and undo](#setup-and-undo)) after
each assistant message, with the session's JSON on stdin. It reads
`session_id` and `transcript_path` and ignores every other field. It prints
one line and always exits 0, since Claude Code shows nothing for a command
that fails:

| line | when |
| --- | --- |
| `weir: C in context, S sent` | the session's files were read in full, and every one in a format the audit recognises |
| `weir: C in context, S sent, part unknown` | as above, but some of the session is unknown (below), and C or S is not 0 |
| `weir: unknown` | some of the session is unknown, and nothing was found in the rest: the counts would be a false zero |
| `weir: checking P%` | the session is not read in full yet (see [Speed](#speed-and-the-cache)); P% of its bytes are; nothing found so far |
| `weir: C in context, S sent, checking P%` | the same, with what was found so far |
| `weir: no session` | stdin is not the status line JSON, or has no transcript path or no session id that is a plain name (it holds a `/`, or starts with a `.`, say) |
| `weir: error, run /weir` | the inventory inputs cannot be used (a wrong key, say), or the cache cannot be written; `/weir` prints the inventory's error |

`--inventory`, `--store` and `--key` are the three inputs of `weir audit`,
and `--cache` the directory for what earlier runs read. None has a default
here: setup writes them all into the command.

### What is counted

The session is audited as `weir audit` audits it ([docs/audit.md](audit.md)),
and from its hits:

- **in context** (C) counts the credentials whose value entered the agent's
  context: a credential with a `context` hit, or a `tool_call` hit by value
  (the agent wrote the value, so it had it);
- **sent** (S) counts the credentials sent out in a tool call, by value or
  by name: a credential with any `tool_call` hit, form `name` included
  ([References by name](audit.md#references-by-name)).

A credential sent by value is in both counts; one sent only by name is in
S only, since its value never entered the context. `stored` hits are not
counted. Credentials are counted, not inventory records: records whose
stored fingerprints are equal (the same secret found in the launch
environment and in a project `.env`, say) count once, and so do the
records of an environment variable that share its name (`GITHUB_TOKEN`
assigned in the launch environment and in `~/.bashrc`: records whose
`detectors` hold `launch_env` or `startup_file`), whether the hit was by
value or by name. A credential shape found loose in a startup file is not
a variable: two such shapes of one kind are two credentials. The /weir
report lists every record of a credential in its one block.

Some of the session is **unknown** when the audit of any of its files is
incomplete ([docs/audit.md](audit.md#unknown): an unrecognised format, a
line that is not a record, a hit whose kind is unknown), when the
transcript is missing, or when the session's directory holds a symbolic
link or an entry that is not a regular file or directory.

### The session's files

The session is the transcript Claude Code names, and every file in the
session's own directory beside it, `<transcript directory>/<session id>/`:
subagent transcripts (`subagents/*.jsonl`) and their sidecars, saved large
tool outputs (`tool-results/*`), and anything else Claude Code keeps there.
`CLAUDE_CONFIG_DIR`, when set, is handed to the audit as `weir audit`
hands it.

### Speed and the cache

Claude Code cancels a status line run that is still going when the next
one starts, and the audit reads about a megabyte of text in a few seconds,
so the segment reads a session in steps and keeps what each step found:

- A file is read in chunks of whole lines (64 KiB, or one line when a line
  is longer). Each chunk is audited as the format of the whole file, with
  `weir.audit.audit_chunks`. A file's lines are records each on its own, so
  the chunks of a file give the hits the whole file gives. A format read
  as a whole (an OTLP file, a subagent sidecar) is one step.
- After each step the cache is written, so a cancelled run loses at most
  the step it was in. A run stops taking new steps once `--budget-ms`
  (default 500) has passed, and always takes at least one, so every run
  moves the reading on. A session not read in full shows `checking P%`.
- A file is read again only from where the last run stopped, as long as it
  is the same file (device and inode), it only grew, and the part already
  read is unchanged at both ends: its first 4 KiB, and the 4 KiB before
  that point. A refresh of a Claude Code session file then reads those two
  windows and the bytes appended since, never the part already read.
  Anything else (a file that shrank, was replaced, or changed at either
  end), and the file is read from the start. A file unchanged since a run
  that read it in full (same size and modification time) is not read at
  all. A change inside the read part that leaves both ends, the size and
  the inode as they were is not seen: Claude Code appends to a session
  file, and reading the whole part again is what this avoids.
- A first read takes the file's format from its first whole lines when
  they hold a Claude Code message record (the file is then a session file
  whatever the rest holds), so the time before the first step does not
  grow with the file. Otherwise the whole file is recognised as
  `weir audit` recognises it.
- The bytes after a file's last line end (a line still being written) are
  audited as a whole line would be, and again once the file changes; they
  are never taken as read lines.

A long session, or a large tool output, can take several runs to read,
and Claude Code runs the status line only on events (a new assistant
message, say). To keep it reading while a session is idle, set
`statusLine.refreshInterval` (seconds) in the settings; setup does not set
it for you.

The cache is one file per session in `--cache`, written owner-only
(0600, directory 0700). It holds credential ids, byte offsets, sizes,
times, device and inode numbers, and HMAC-SHA256 values under the
inventory's fingerprint key (of a file's path, of a file's first 4 KiB and
of the 4 KiB before an offset, of the inventory inputs). It holds no
value, no fragment of one, no file name and no unkeyed hash. A new inventory (other report or store
bytes) starts every cache over. Deleting the directory is always safe.

### Beside an existing status line

With `--inner COMMAND`, the segment runs `COMMAND` in a shell with the same
JSON on stdin, while it reads the session, and prints that command's
output first, then ` | ` and the segment on its last line. A command that
exits non-zero, prints nothing, or runs more than 10 seconds shows the
segment alone, as Claude Code would show nothing for it. When Claude Code
cancels the run, the command is stopped with it. Its error output is
discarded.

## The /weir report

```sh
weir statusline report --inventory REPORT --store STORE --key KEY --session ID [--claude-dir DIR]
```

It audits the session's files in full, with no cache, and prints:

1. the segment line, for the whole session;
2. `session: <transcript> (<N> files read)`;
3. one block per credential with a hit, counted as the segment counts
   them (the records of one value or one variable together), most severe
   state first (sent, then in context, unknown, stored), then by name:

```text
ACME_API_TOKEN (launch env)
  source: launch env, the environment Claude Code starts with
  entered the context: 1 time, first at turn 2: the Bash tool result, /home/me/.claude/projects/-home-me-app/4b9f.jsonl:5
  sent in a tool call: 1 time by value, first at turn 3: the Bash tool call, argument command, /home/me/.claude/projects/-home-me-app/4b9f.jsonl:7
  now sits in: /home/me/.claude/projects/-home-me-app/4b9f.jsonl; and in the conversation the model received; and wherever the Bash tool call sent it
  advice: rotate it at its issuer; remove ACME_API_TOKEN from the environment Claude Code starts with; delete the session files above once it is rotated
```

4. `not found in this session: N credentials; not checkable: M credentials`,
   counted the same way (a credential is not checkable when none of its
   records is), then the audit's `unknown:` lines.

The lines of a block:

| line | what it says |
| --- | --- |
| heading | the credential as the audit prints it: inventory name, location and scope; for several records, each name once with every place it was found, `GH_TOKEN (launch env, ~/.bashrc)` |
| `source` | where the inventory found it: the location and scope, and the source in words, for each record, separated by `;` |
| `entered the context` | how many places in the session put the value in the context, and the first: its turn, what it sat in (a tool result, a prompt, the model's own text, a subagent's), its file and line. A place every record of the credential matches (a `$NAME` that names both) is one place; one held by value and named there counts by value |
| `sent in a tool call` | how many places in tool calls, `by value`, `by name` or both, and the first: its turn, the tool, the argument, its file and line |
| `unknown` | hits whose kind the audit cannot tell, and the first |
| `now sits in` | the session files that hold the value, then the conversation the model received when the value entered the context, and wherever each tool sent it; for a credential sent by name only, that no session file holds the value |
| `advice` | rotate it at its issuer; for each record, remove it from the launch environment, or take it out of the file it came from or deny the agent read access to that file; delete the session files that hold it once it is rotated. A credential only `stored` or `unknown` gets what to check instead |


Every string in it comes from the audit report, which already applied the
audit's [printing rule](audit.md#printing), or is a number or a fixed word.

**Turns.** Turn N starts at the Nth prompt the person typed in the main
transcript: a `user` record, not `isMeta`, whose content is a string or
holds a `text` block and no `tool_result` block. Records before the first
prompt are turn 0. A hit in a subagent transcript
(`subagents/<agent>.jsonl`) takes the turn of the tool call that started
the subagent: the main transcript's `tool_use` whose id is the `toolUseId`
in the subagent's sidecar (`<agent>.meta.json`), else an unknown turn.

**The command.** Setup installs `/weir` as a Claude Code command file,
`<Claude config dir>/commands/weir.md`, with `disable-model-invocation:
true`. Its `` !`...` `` line runs this report for `${CLAUDE_SESSION_ID}`
before the prompt reaches the model, and the command's `allowed-tools`
allows exactly that command line. The prompt asks the model to show the
report as printed. The report holds no value, so neither does what the
model sees.

`--session` takes a session id (a plain name, else exit 2) and finds
`<Claude config dir>/projects/*/<id>.jsonl`, the config directory being
`--claude-dir`, else `CLAUDE_CONFIG_DIR`, else `~/.claude`. No transcript,
or more than one, is exit 2. Unusable inventory inputs, or a file the
audit refuses, are exit 2 with the audit's error. Otherwise the exit code
is 0.

## Setup and undo

```sh
weir statusline setup --inventory REPORT --store STORE --key KEY [--cache DIR] [--claude-dir DIR] [--dry-run]
weir statusline undo [--cache DIR] [--dry-run]
```

`--cache` defaults to `~/.weir/statusline`; `--claude-dir` to
`CLAUDE_CONFIG_DIR`, else `~/.claude`.

**Setup** checks the three inventory inputs as the audit does (exit 2 when
they cannot be used), then shows the exact change:

- In `<Claude config dir>/settings.json` (where a symbolic link points,
  when it is one), `statusLine` before and after. The new `statusLine`
  keeps every key of the old one (`padding`, `refreshInterval`, ...), sets
  `type` to `command`, and sets `command` to the segment's command line,
  with the old command, when there is one, passed as `--inner`: the
  existing status line keeps running, and its output comes first. Every
  other setting is kept; the file is written as JSON indented by 2 spaces.
  A `statusLine` printed in the dry run that holds an inventoried
  credential, in any form the audit matches, is withheld.
- The new command file `<Claude config dir>/commands/weir.md`, line by
  line.

The commands it writes start weir as `<this Python> -m weir`, with every
path absolute, so they do not depend on the PATH Claude Code runs them
with.

With `--dry-run` it stops there. Otherwise it asks, and writes only when
the answer is exactly `yes`, lower-case; any other answer (`y`, `YES`),
or no input, writes nothing. When it writes, it writes first the undo record,
`<cache>/setup-undo.json`, then a copy of the settings file's bytes before
setup, `settings.json.weir-backup` beside it (owner-only), then the files,
each atomically, keeping the settings file's permissions. Just before it
writes, it reads each file again, and refuses, writing nothing, when one
changed since the change was shown (Claude Code saving a setting while
the prompt waited, say).

Setup refuses, and writes nothing, when an undo record exists (it is
already set up), when the settings file is not a JSON object or its
`statusLine` is not an object, when the status line already runs the weir
segment, or when a different `commands/weir.md` exists.

**Undo** reads the undo record and shows what it will do: put each file
setup changed back to its bytes before setup, from its backup, and remove
each file and directory setup created. With `--dry-run` it stops there;
otherwise it asks, as setup does. It refuses, and writes nothing, when a
file changed after setup (its keyed MAC is not the one the record holds
for the bytes setup wrote), naming the file, and checks again just before
it writes: restoring the old bytes would throw that change away. After undo the files are byte for byte what they
were, and the backup and the record are gone. With no undo record it says
there is nothing to undo.

The undo record holds paths (the fingerprint key's among them), the
directories setup created, and an HMAC-SHA256 under the fingerprint key of
each file's bytes as setup wrote them: no unkeyed hash of a settings file,
which may hold a credential. Undo needs the key setup used. The backup
holds the settings file's own bytes, beside it, as private as the file.

**The key.** Every command here reads the fingerprint key from a file
only its owner can read, as `weir inventory` creates it (mode 0600). A key
file another user owns, or that others can read or write, is refused
(`weir: error, run /weir` on the line, exit 2 from the report and setup),
never used and never repaired.

## What it does not claim

- Everything [`weir audit` does not claim](audit.md#what-the-audit-does-not-claim).
- The segment counts what the session's files hold now. A session Claude
  Code compacted or rewrote is read as its files are.
- It reads the session's files only: not `CLAUDE.md` or memory files
  (audit them with `weir audit`), and not telemetry.
- A count is not a guard: nothing here stops a credential from reaching
  the agent. Rules that keep the agent from reading a file, and an
  environment without the credential, do.

## Testing against this contract

`packages/weir/tests/test_statusline_acceptance.py` was written before the
implementation. Every fixture is a fake session in a fake Claude config
directory, under a fake home inventoried by the real `weir inventory`; what
the segment should show is read from a real `weir audit --json` run over
the same files through the rule in [What is counted](#what-is-counted),
and checked against where the fixture put each value. No fixture is built
from a real session, setting or credential.

`packages/weir/tests/test_statusline_large_session.py` generates a fake
transcript of about 50 MB and checks the incremental read: a first refresh
reads the whole file, and a refresh after a few appended records reads
only those bytes and the two 4 KiB windows, counted outside the code under
test (every read the process makes, and the kernel's `rchar` where it
keeps one), with both timings printed. It also scans every cache file for
each planted value and every 6-character run of one, and checks the key
file's mode.
