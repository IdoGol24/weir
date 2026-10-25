# weir statusline: the Claude Code status-line segment and /weir report

> **Experimental.** Its words, flags and files may change without notice.

> **The contract.** `weir statusline` (in `packages/weir/src/weir/statusline/`)
> implements this document; where code and text disagree, one of them is a bug.

`weir statusline` puts [`weir audit`](audit.md) where a person working with
Claude Code can see it: a segment on Claude Code's status line that counts
how many of their own inventoried credentials entered the current
session's context and how many were sent out in a tool call, and a `/weir`
command that lists each one. It is display only, local and offline, works
from the keyed fingerprints of a [`weir inventory --store`](inventory.md)
run, and never prints, caches or writes a credential value or any run of 6
characters of one.

## The segment

```sh
weir statusline --inventory REPORT --store STORE --key KEY --cache DIR [--inner COMMAND] [--budget-ms N]
```

Claude Code runs this after each assistant message with the session's
JSON on stdin; it reads `session_id` and `transcript_path`. It prints one
line and always exits 0:

| line | when |
| --- | --- |
| `weir: C in context, S sent` | the session's files are read to their end |
| `weir: C in context, S sent, part unknown` | some of it is unknown (below), and C or S is not 0 |
| `weir: unknown` | some of it is unknown and nothing was found: the counts would be a false zero |
| `weir: scanning… P%` | not read to its end yet; `C in context, S sent, ` in front once something is found |
| `weir: partly checked, run /weir` | a long record was not searched whole in three tries, each within its own time bound (below); `weir audit` or `/weir` gives the full counts |
| `weir: no session` | stdin is not the status line JSON |
| `weir: error, run /weir` | the inventory inputs cannot be used (a wrong key, say) |

### What is counted

The session is audited as `weir audit` audits it. **In context** (C)
counts the values with a `context` or `tool_call` hit (the agent wrote the
value, so it had it); **sent** (S) counts the values with a `tool_call`
hit. Values are counted, not inventory records: records whose stored
fingerprints are equal hold one value. `stored` hits are not counted.

Some of the session is **unknown** when the audit of a file read is
incomplete (an unrecognised format, a line that is not a record), when the
transcript is missing or empty, when a file is compressed (gzip), or when
the session's directory holds a file the segment does not read, a symbolic
link, an entry that is not a regular file or directory, or one that cannot
be read or listed.

### The session's files

The transcript Claude Code names, and in the session's own directory
beside it (`<transcript directory>/<session id>/`): the subagent
transcripts (`subagents/*.jsonl`) and their sidecars
(`subagents/*.meta.json`). Saved tool outputs (`tool-results/*`) hold a
value only as stored text, so the segment skips them (a compressed one is
unknown); the `/weir` report reads them.

### Reading in steps

Claude Code cancels a status line run that is still going when the next
one starts. So the transcripts are read in steps of whole lines (64 KiB,
or one line when a line is longer), and after each step a checkpoint is
written atomically to `--cache`: a run that is cancelled at any moment
loses at most that step, and the next run reads on from where the last
one stopped. A run takes new steps until `--budget-ms` (default 500) has
passed, and always takes one. A file is read on only while it is the same
file (device and inode), it has not shrunk, and the 4 KiB before the point
reached are unchanged; otherwise it is read again from the start. A last
line without its line end, in a file changed in the last 5 seconds, is a
record still being written: it counts as unread, so the line shows
`scanning…`. Once it stops changing it is audited as it is. A file's
format is recognised once, from the first step that is recognised as one,
and every later step is audited in that format: a step that holds only
records the format does not name (a `system` or `progress` record, say)
counts as `weir audit` counts them in the whole file. Steps before it that
were recognised as no format (what Claude Code writes before the first
prompt, say) are read again in that format. A file no step is recognised
in is unknown.

Every record is searched whole, the data of its base64 images aside
(which the audit never searches, [docs/audit.md](audit.md)). A long
record (over 128 KiB, its image data aside) is searched only as the first
step of a run: a run that has already taken a step leaves it for the
next, which reads that record's file first. A long record has a time
bound of its own, 5 seconds, whatever `--budget-ms` says: Claude Code
cancels a run only when it starts the next one. Before each try at it,
the checkpoint names its offset and counts the try. A try that is
cancelled or runs out of time leaves the record to the next run; after
three such tries in a row the run moves past it without searching it
again. The session is then **partly checked**: the line shows
`weir: partly checked, run /weir`, never a number and never a zero, for
as long as the session is read. `weir audit` of the session's files, or
the `/weir` report, which audits them whole, gives the full counts.

- `--budget-ms` bounds the steps of shorter records only: with
  `--budget-ms 0` a long record is still searched, within its own bound.
- A run that starts with a long record can last up to its 5 seconds more
  than `--budget-ms` (and the existing status line command, below, up to
  10 seconds before it).
- A long last line without its line end, once it stopped changing, is
  searched again by every run until it ends; three of those runs
  cancelled in a row leave the session partly checked.
- On Windows there is no timer: a long record is searched to its end,
  however long that takes, and a cancelled try still counts.

The checkpoint is owner-only and holds credential ids, byte offsets, device
and inode numbers, each file's format, whether a record was skipped, the
offset of a long record being searched and the count of its tries, and
HMAC-SHA256 values under the fingerprint key: no value, no fragment of
one, no file name. A new inventory starts it over. Deleting the `--cache`
directory is always safe.

### Beside an existing status line

With `--inner COMMAND`, the command already in the settings runs first in
a shell with the same JSON on stdin, and its output is printed before
` | ` and the segment. One that exits non-zero, prints nothing or runs
more than 10 seconds shows the segment alone, as Claude Code would show
nothing for it. The command runs in a process group of its own, which is
killed whole at the 10 second bound and when the run is cancelled
(SIGTERM, SIGINT or SIGHUP). A child that leaves that group (`setsid`, or
a daemon that detaches itself) is not stopped, and neither is a
background job still running after the command itself has exited, nor
anything when the run is killed with SIGKILL.

## The /weir report

```sh
weir statusline report --inventory REPORT --store STORE --key KEY --session ID [--claude-dir DIR]
```

It audits the session's files in full (saved tool outputs included) and
prints the segment line, the transcript read, and one block per value that
reached the session, most severe first:

```text
ACME_API_TOKEN (launch env)
  source: launch env, the environment Claude Code starts with
  entered the context: 2 times, first at turn 2: the Bash tool result, <transcript>:5
  sent in a tool call: 1 time, first at turn 3: the Bash tool call, argument command, <transcript>:7
  now sits in: <transcript>; and in the conversation the model received; and wherever the Bash tool call sent it
  advice: rotate it at its issuer; remove ACME_API_TOKEN from the environment Claude Code starts with; delete the session files above once it is rotated
```

A value found in several places lists them all; one a shell startup file
exports says so, and its advice is to take it out of that file. Turn N
starts at the Nth prompt the person typed: a `user` record that is not
`isMeta`, `isCompactSummary` or `isVisibleInTranscriptOnly`, is not a
tool result, holds text, an image or a document, and is not a local slash
command, a shell command run with `!`, their output or an interrupt note
(text starting `<command-name>`, `<command-message>`, `<command-args>`,
`<local-command-…>`, `<bash-input>`, `<bash-stdout>`, `<bash-stderr>` or
`[Request interrupted by user`). A subagent's hit takes the turn of the
tool call that started it, from its sidecar. `--session` takes a plain session id
(else exit 2) and finds `<Claude config dir>/projects/*/<id>.jsonl`.

Setup installs the report as the `/weir` command
(`<Claude config dir>/commands/weir.md`), whose `!` line runs it for
`${CLAUDE_SESSION_ID}`.

## Setup and undo

```sh
weir statusline setup --inventory REPORT --store STORE --key KEY [--cache DIR] [--claude-dir DIR] [--dry-run]
weir statusline undo [--claude-dir DIR] [--dry-run]
```

`--cache` defaults to `~/.weir/statusline`, `--claude-dir` to
`CLAUDE_CONFIG_DIR`, else `~/.claude`. Setup supports POSIX shells (Linux,
macOS) only for now and refuses on Windows (exit 2).

**Setup** shows the exact change: the segment `statusLine` will run in
`settings.json`, and the new `commands/weir.md`. The new `statusLine`
keeps every key of the old one and runs the segment with the old command
as `--inner`; that command is kept but never shown, as it may hold a
credential, and every other setting is kept. Setup and undo read no key
and compute no HMAC. It writes only on the exact line `yes`, and refuses when
the settings are not a JSON object, the status line already runs weir, a
different `commands/weir.md` exists, or it is already set up. It keeps the
settings file's bytes beside it as `settings.json.weir-backup`
(owner-only), or, when there is no settings file, leaves an empty
`settings.json.weir-created`, then writes the command file, then the
settings, reading the settings again first and refusing if they changed
since it showed them.
The undo it prints names `--claude-dir`, when given, as an absolute
path, so it runs from any directory.

**Undo** shows what it does and, on `yes`, puts back the `statusLine` the
backup holds (or removes it when there was none) while the status line
is still exactly the one setup wrote: the interpreter running `-m weir
statusline` with setup's options, and `--inner` the command from before
setup, when there was one. Every other setting is kept; when nothing
else changed it writes the backup's bytes back (an empty file comes back
empty), or removes the settings file when there was none before setup. It
then removes `commands/weir.md` and the backup or marker. When the status
line changed since setup, or the settings file was removed and there was
one before setup (even an empty one), it refuses and writes and deletes
nothing; its message names the backup, which holds the settings from
before setup, and `commands/weir.md`, to delete once the status line is
put back by hand. With no settings file before setup, a removed
`settings.json` leaves nothing to restore: undo removes `commands/weir.md`
and the marker. An interrupted setup or undo leaves both usable: running
undo again finishes it. The checkpoints in setup's
`--cache` stay; deleting them is safe.

**The key.** `weir statusline`, `weir statusline report`, `weir inventory`
and `weir audit` read the fingerprint key from a file only its owner can
read, as `weir inventory` creates it (mode 0600): one another
user owns, or that others can read or write, is refused, never repaired.

## What it does not claim

- Everything [`weir audit` does not claim](audit.md#what-the-audit-does-not-claim).
- It counts what the session's files hold now, and a value sent by value
  only: a tool call that names a variable (`$TOKEN`) is not counted.
- A rewrite inside the part of a file already read that keeps its end and
  its size is not seen.
- A count is not a guard: nothing here stops a credential from reaching
  the agent.
- A long record not searched whole within its time bound in three tries
  in a row, each cancelled or out of time, leaves the session partly
  checked rather than counted, where `weir audit` of the whole file counts
  it. Refreshes closer together than its search takes (a search of 0.3 s,
  say, and refreshes 0.3 to 0.6 s apart) can do that to an ordinary
  large tool result, and a slow or busy machine makes it likelier.
- Undo after any other change to the settings writes them back at an
  indent of 2.
