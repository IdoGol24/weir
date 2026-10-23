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
| `weir: scanning… P%` | the session is not read in full yet (see [Speed](#speed-and-the-cache)); P% of its bytes are; nothing found so far |
| `weir: C in context, S sent, scanning… P%` | the same, with what was found so far |
| `weir: no session` | stdin is not the status line JSON, or has no transcript path or no session id that is a plain name (it holds a `/`, or starts with a `.`, say) |
| `weir: error, run /weir` | the inventory inputs cannot be used (a wrong key, say), or the cache cannot be written; `/weir` prints the inventory's error |

`--inventory`, `--store` and `--key` are the three inputs of `weir audit`,
and `--cache` the directory for what earlier runs read. None has a default
here: setup writes them all into the command.

### What is counted

The session is audited as `weir audit` audits it ([docs/audit.md](audit.md)),
and from its hits:

Values are counted, not inventory records: records whose stored
fingerprints are equal hold one value (the same secret found in the launch
environment and in a project `.env`, say) and count once, and two
different values count twice, even under one variable name (`GH_TOKEN` in
the launch environment and, with another value, exported in `~/.bashrc`).

- **in context** (C) counts the values that entered the agent's context: a
  value with a `context` hit, or a `tool_call` hit by value (the agent wrote
  the value, so it had it);
- **sent** (S) counts what was sent out in a tool call: each value with a
  `tool_call` hit by value, and each environment variable a tool call sent
  by name (a hit of form `name`,
  [References by name](audit.md#references-by-name)). A variable sent by
  name counts once for its name, however many records hold it, and not at
  all when a value of a record of that name is already counted as sent by
  value: the shell sent one of its values, and which one the session does
  not say.

A value sent by value is in both counts; a variable sent only by name is
in S only, since its value never entered the context. `stored` hits are
not counted. An environment variable is a record whose `detectors` hold
`launch_env` or `startup_file`; a credential shape found loose in a
startup file is not one. The /weir report lists the records of one value
in one block, and with them the records of the same variable that hold no
other value (a `$(gh auth token)` export beside the token itself).

Some of the session is **unknown** when the audit of any of its files is
incomplete ([docs/audit.md](audit.md#unknown): an unrecognised format, a
line that is not a record, a hit whose kind is unknown, an empty file, a
file compressed with gzip, which the audit does not scan), when the
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

- A file is read in steps of whole lines (64 KiB, or one line when a line
  is longer). Each step is audited as the format of the whole file, with
  `weir.audit.audit_chunks`. A file's lines are records each on its own, so
  the steps of a file give the hits the whole file gives.
- In a text format (a saved tool output, a `CLAUDE.md` or memory file, an
  unknown file) a step holds at most 256 KiB: a longer line, or a file
  with no line end at all, is read in windows of that size that overlap
  by at least 32 KiB, and by more than six times the longest value the
  inventory store gives a length for, so a value one window's end cuts is
  whole in the next. The offset kept is inside the line. A line of a
  JSON Lines format (a Claude Code session file) is one record and is
  read whole in one step, however long.
- The format is the one `weir audit` recognises, taken from the file's path
  and the lines read so far, never by reading the whole file first: a
  saved tool output (`tool-results/*`) is one whatever its lines hold, and
  a session file stays one once a line is a message record. A line that
  changes the format (in the part read, in the bytes after the last line
  end, or appended later) has the file read again from the start in the
  new format. A line that makes it a whole-file format, or a file the path
  and lines leave unknown whose first line is not a JSON object of its own
  but which starts with `{` (it may be one OTLP export request,
  pretty-printed), is read whole in one step when it is at most 1 MiB. A
  larger one is read in steps as unknown text: what it holds is not
  counted, and the session is part unknown, never a false zero.
- A file that starts with the gzip magic bytes is not read: `weir audit`
  does not scan it, and the session is part unknown.
- After each step the cache is written: it is the checkpoint the next run
  resumes from (per file, the byte offset reached, the keyed MACs that
  show the part read is unchanged, and the credential ids found so far).
  It is written whole, to a temporary file then renamed over the old one,
  so a run Claude Code cancels at any moment loses at most the step it was
  in and never leaves a half-written checkpoint. A run ended by SIGTERM
  removes its temporary file; one ended by SIGKILL can leave it, and a
  later run removes it once it is a minute old. A run stops taking new
  steps once `--budget-ms` (default 500) has passed, and always takes at
  least one, so every run moves the reading on, cancelled or not. A
  session not read to the end of every file shows `scanning… P%`.
- A step holds only its own bytes: a run reads on from the offset, never
  the rest of the file at once. Only a file read whole (above) is read in
  full in one step.
- A file is read again only from where the last run stopped, as long as it
  is the same file (device and inode), it only grew, and the part already
  read is unchanged at both ends: its first 4 KiB, and the 4 KiB before
  that point. A refresh of a file read in steps then reads those two
  windows, the bytes appended since, and one block (below), never the rest
  of the part already read; a file read whole is read whole again.
  Anything else (a file that shrank, was replaced, or changed at either
  end), and the file is read from the start. A file whose size is
  unchanged but whose modification time changed was rewritten in place
  (an append changes the size), and is read from the start at once.
- The part already read is also kept as a keyed MAC of each whole 1 MiB
  block, and each refresh checks one block, in turn, against its MAC: a
  block that changed has the file read from the start. So a rewrite
  inside the read part that keeps both ends (and comes with an append, so
  the size changes too) is found within as many refreshes as the file has
  blocks, at the cost of reading one block per refresh. Finding it at once
  would mean reading the whole read part on every refresh, which is what
  this design avoids.
- The bytes after a file's last line end (a line still being written) are
  audited as a whole line would be, and again once the file changes; they
  are never taken as read lines. In a Claude Code session file they are a
  record Claude Code is still writing while the file changed in the last
  5 seconds: not counted, and not unknown, until the line is whole. When
  they stay as they are for longer (a session that stopped mid-line), they
  are audited, and the session is part unknown.

A long session, or a large tool output, can take several runs to read,
and Claude Code runs the status line only on events (a new assistant
message, say). To keep it reading while a session is idle, set
`statusLine.refreshInterval` (seconds) in the settings; setup does not set
it for you.

The cache is one file per session in `--cache`, written owner-only
(0600, directory 0700). It holds credential ids, byte offsets, sizes,
times, device and inode numbers, each file's format and yes/no flags of
what its lines showed of it, and HMAC-SHA256 values under the
inventory's fingerprint key (of a file's path, of a file's first 4 KiB,
of the 4 KiB before an offset, of each whole 1 MiB block read, of the
inventory inputs). It holds no
value, no fragment of one, no file name and no unkeyed hash. A new inventory (other report or store
bytes) starts every cache over. Deleting the directory is always safe.

### Beside an existing status line

With `--inner COMMAND`, the segment runs `COMMAND` in a shell with the same
JSON on stdin, while it reads the session, and prints that command's
output first, then ` | ` and the segment on its last line. A command that
exits non-zero, prints nothing, or runs more than 10 seconds shows the
segment alone, as Claude Code would show nothing for it. Its error output
is discarded.

The command runs in a process group of its own, so stopping it stops
everything it started. It is stopped when it runs past 10 seconds, when
Claude Code cancels the run (SIGTERM), and, half a second after the
command itself exits, when a child it left in the background still holds
its output open: the output printed until then is shown. Nothing it
starts outlives the run. On a system without process groups only the
command itself is stopped.

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
| `source` | where the inventory found it: the location and scope, and the source in words, for each record, separated by `;`. A record a shell startup file holds says so: `~/.bashrc, a shell startup file that exports it into the environment` |
| `entered the context` | how many places in the session put the value in the context, and the first: its turn, what it sat in (a tool result, a prompt, the model's own text, a subagent's), its file and line. A place every record of the credential matches (a `$NAME` that names both) is one place; one held by value and named there counts by value |
| `sent in a tool call` | how many places in tool calls, `by value`, `by name` or both, and the first: its turn, the tool, the argument, its file and line |
| `unknown` | hits whose kind the audit cannot tell, and the first |
| `now sits in` | the session files that hold the value, then the conversation the model received when the value entered the context, and wherever each tool sent it; for a credential sent by name only, that no session file holds the value |
| `advice` | rotate it at its issuer; for each record, remove it from the launch environment, take it out of the shell startup file that exports it (removing it from the environment alone, the next shell puts it back), or take it out of the file it came from or deny the agent read access to that file; delete the session files that hold it once it is rotated. A credential only `stored` or `unknown` gets what to check instead |


Every string in it comes from the audit report, which already applied the
audit's [printing rule](audit.md#printing), or is a number or a fixed word.

**Turns.** Turn N starts at the Nth prompt the person typed in the main
transcript: a `user` record whose content is a string or holds a `text`
block and no `tool_result` block. A record marked `isMeta`,
`isCompactSummary` (the summary compaction writes) or
`isVisibleInTranscriptOnly` is not a prompt, and neither is the record of
a local slash command or its output: text that starts with
`<command-name>`, `<command-message>`, `<command-args>`,
`<local-command-stdout>`, `<local-command-stderr>` or
`<local-command-caveat>`. Records before the first
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

**Setup** supports POSIX shells (Linux, macOS) only for now. On Windows
it refuses (exit 2) before reading anything: the segment runs the
existing status line command through the system shell, which there is not
the shell the command was written for.

It checks the three inventory inputs as the audit does (exit 2 when
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
the answer is exactly the line `yes`, lower-case, with nothing before or
after it; any other answer (`y`, `YES`, ` yes`, `yes `), or no input,
writes nothing. When it writes, it writes first the undo record,
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
otherwise it asks, as setup does, and writes only on the exact answer
`yes`. After undo the files are byte for byte what they were, and the
backup and the record are gone. Undo also removes the status line's
checkpoints from `--cache` (the files named after a session's keyed MAC,
and any temporary file a killed run left), then each directory of
`--cache` and its parents that setup created and that is now empty; a
directory that existed before setup (`~/.weir`, holding the key, say)
stays. A Claude Code session still running with the old settings can
write a checkpoint again until it reloads them. With no undo record it
says there is nothing to undo.

When the settings file changed after setup (its keyed MAC is not the one
the record holds for the bytes setup wrote) but its `statusLine` is still
exactly the one setup wrote (Claude Code saved another setting, say),
restoring the old bytes would throw that change away. Undo then says so,
and on `yes` puts back only the `statusLine` that was there before setup
(from the backup, an explicit `null` included), or removes the key when
there was none, and keeps every other key as it is now, written as JSON
indented as the file was before setup (2 spaces when it had no
indentation to go by). When the result is the same content as the file
before setup (only the formatting changed since), undo puts back the
file's exact bytes from before setup instead, or removes a file setup
created. When the `statusLine` itself changed, or the file is not a JSON
object, undo refuses, writes nothing, and names the file. Undo reads each
file again just before it writes, and refuses if one changed since it
showed the change. It does not print the old `statusLine`, which may hold
a credential.

The undo record holds paths (the fingerprint key's among them), the
directories setup created, and HMAC-SHA256 values under the fingerprint
key of each file's bytes as setup wrote them and of the `statusLine` it
wrote: no unkeyed hash of a settings file, which may hold a credential.
Undo needs the key setup used. The backup holds the settings file's own
bytes, beside it, as private as the file.

**The key.** Every command here reads the fingerprint key from a file
only its owner can read, as `weir inventory` creates it (mode 0600). A key
file another user owns, or that others can read or write, is refused
(`weir: error, run /weir` on the line, exit 2 from the report and setup),
never used and never repaired.

## What it does not claim

- Everything [`weir audit` does not claim](audit.md#what-the-audit-does-not-claim).
- The segment counts what the session's files hold now. A session Claude
  Code compacted or rewrote is read as its files are.
- It reads the session's files only: the transcript and the session's
  own directory (a `CLAUDE.md` there included), not the project's
  `CLAUDE.md` or memory files (audit them with `weir audit`), and not
  telemetry.
- A rewrite inside the part of a file already read is found at once when
  the file's size is unchanged, and otherwise within as many refreshes as
  the file has 1 MiB blocks ([Speed and the cache](#speed-and-the-cache)).
- A reference by name counts however the shell would quote it
  (`'$NAME'` counts): see [References by name](audit.md#references-by-name).
- A single line of a Claude Code session file is one record and is read in
  one step, however long it is (a pasted file kept inline, say).
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
only those bytes, the two 4 KiB windows and the one 1 MiB block it
checks, counted outside the code under
test (every read the process makes, and the kernel's `rchar` where it
keeps one), with both timings printed. It also scans every cache file for
each planted value and every 6-character run of one, and checks the key
file's mode. A last test runs the real `python -m weir statusline`
process on that transcript and kills it, with SIGTERM and SIGKILL in turn,
at a random point after each run saved a checkpoint, again and again: a
run after each kill shows `scanning…` and progress that never goes back,
the scan completes, its counts equal those of one uninterrupted scan, and
every checkpoint and leftover temporary file is value-free.
