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
characters of one. Setup can also add a [redaction hook](#the-redaction-hook)
that replaces those credentials in tool results before the model sees them,
and in the copy Claude Code saves of a large one.

![Terminal recording: the status line under a fake Claude Code session counts up while it scans and settles on "weir ⚠ 2 entered · 1 sent → /weir", then /weir is typed and reports each of the two fake credentials: where it came from, the turn and tool call that moved it, where it now sits, and the advice to rotate it.](assets/statusline.svg)

For example, `weir ⚠ 2 entered · 1 sent → /weir`, or `weir ✓ no known
key seen` when none did. It reads the session's transcript and its subagent
transcripts; a file it cannot read makes it say `unknown`, never a false
zero.

## The segment

```sh
weir statusline --inventory REPORT --store STORE --key KEY --cache DIR [--inner COMMAND] [--budget-ms N] [--markers DIR]
```

Claude Code runs this after each assistant message with the session's
JSON on stdin ([Claude Code's status line
input](https://code.claude.com/docs/en/statusline)); it reads
`session_id`, `transcript_path`, and the session's project folder (below)
from `workspace.project_dir`, else `cwd`. It prints one line and always
exits 0:

| line | when |
| --- | --- |
| `weir ✓ no known key seen` | the session's files are read to their end, nothing is unknown, no value entered the context or was sent, and the session is in the inventory's project (below) |
| `weir project not inventoried` | as for `✓ no known key seen`, but the session is not in the inventory's project, the inventory has no project, or the JSON names no project folder |
| `weir ⚠ C entered · S sent → /weir` | the session's files are read to their end, and C or S is not 0 |
| `weir ⚠ C entered · S sent · part unknown → /weir` | some of it is unknown (below), and C or S is not 0 |
| `weir … · possibly not redacted` | with the redaction hook: a tool result went to the model without it, or its saved copy was not rewritten (below). The flag follows what the line says otherwise (`unknown`, `scanning… P%`, `partly checked` or the counts, so never a false zero), before any `→ /weir`, and where that would be `✓ no known key seen` or `project not inventoried`, the final counts `⚠ 0 entered · 0 sent` stand instead |
| `weir unknown` | some of it is unknown and nothing was found: the counts would be a false zero |
| `weir scanning… P%` | not read to its end yet; `⚠ C entered · S sent · ` in front once something is found |
| `weir partly checked → /weir` | a long record was not searched whole in three tries, each within its own time bound (below); `weir audit` or `/weir` gives the full counts |
| `weir nothing to check` | the inventory holds no credential weir can check: there is nothing to count, so never `✓ no known key seen` |
| `weir no session` | stdin is not the status line JSON |
| `weir error → /weir` | the inventory inputs cannot be used (a wrong key, say) |

With the redaction hook, ` · K kept out` follows the green words,
`project not inventoried` or the counts once the hook has kept out keys
of K inventory names. Only a session read to its end with nothing
unknown, nothing found and no tool result the hook did not finish, in the
inventory's project, against an inventory that holds a credential weir
can check, says `✓ no known key seen`; one still scanning, partly
checked, unknown or outside that project never does. The line names no
credential and holds no value, so a shared screen gives nothing away.

### Colours

The line is drawn with ANSI SGR codes, which Claude Code's status line
renders:

| part | colour |
| --- | --- |
| `✓ no known key seen` | green (32) |
| `⚠`, `C entered` when C is not 0, and `possibly not redacted` | amber (33, yellow in most terminal themes) |
| `S sent` when S is not 0 | red (31) |
| a count of 0, `part unknown`, `scanning… P%`, `unknown`, `partly checked → /weir`, `project not inventoried`, `nothing to check`, `no session`, `error → /weir` | dim (2) |
| `weir`, `·`, `K kept out`, and `→ /weir` after the counts | the terminal's own |

Every coloured part ends with a reset (0), so the status line beside it
(below) keeps its own colours. When `NO_COLOR` is set and not empty
([no-color.org](https://no-color.org)), the line has the same words and
symbols and no escape code.

### The project

The inventory covers one project at a time: the folder its `weir
inventory --project` walked (`inputs.project` in its report), whose files
it read keys from. The session is **in the inventory's project** when its
project folder is that folder or under it, both resolved to absolute
paths. Anywhere else the inventory does not know the keys in the project's
files, so the line counts the inventory's keys as everywhere but is never
green: where `✓ no known key seen` would show, it shows `project not
inventoried`. With no project in the inventory, or no project folder in
the JSON, the session is never in it, and a folder that is not an
absolute path (`.`, `~/proj`, `$NAME`), or holds what no path Claude Code
passes can (a NUL, a lone surrogate), is no project folder: Claude Code
passes absolute ones, and weir never resolves one against its own folder.

### What is counted

The session is audited as `weir audit` audits it. **Entered** (C)
counts the values with a `context` or `tool_call` hit, the values the model
saw (the agent wrote the value, so it had it); **sent** (S) counts the
values with a `tool_call` hit; **kept out** (K) counts the inventory names
the redaction hook's markers say it replaced. Values are counted, not inventory records: records whose stored
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
(`subagents/*.meta.json`). Saved tool outputs (`tool-results/*`), the
whole copy Claude Code keeps of a large tool output and whose path it gives
the model, hold a value only as stored text, so the segment skips them (a
compressed one is unknown); the `/weir` report reads them. With the
[redaction hook](#the-redaction-hook), the hook rewrites the one a covered
call saved, and a call whose saved output it could not rewrite is flagged.

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
`weir partly checked → /weir`, never a number and never a zero, for
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
one, no file name. A new inventory starts it over. Beside the checkpoints,
`--cache` holds the record of each session's project folder that `/weir`
reads ([The /weir report](#the-weir-report)). Deleting the `--cache`
directory is always safe: until the next refresh, `/weir` then says the
folder is not known yet.

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
anything when the run is killed with SIGKILL. With colour on, a reset
(`ESC[0m`) follows the command's output, so a colour it leaves on never
tints the segment; with `NO_COLOR` its output is printed as it is.

## The redaction hook

```sh
weir statusline hook --inventory REPORT --store STORE --key KEY --markers DIR
```

A Claude Code `PostToolUse` command hook for the Read, Bash, Grep, Glob and
WebFetch tools, with a 10 second timeout, which setup adds when asked
(below). It reads the hook input on stdin and, when the tool's result holds
an inventoried value, prints `hookSpecificOutput.updatedToolOutput`: the
result with each value replaced by `[weir: NAME removed]`, NAME its
inventory name (the first record's, for a value several records hold). It
finds values as `weir audit` does, by keyed fingerprint, in every form of
[docs/audit.md](audit.md#forms), and holds no plaintext key. A raw value,
and a JSON-escaped or URL-encoded one, is replaced exactly; a base64 or hex
one with the whole run it was decoded from, as its edge characters mix bits
of the value with bits of its neighbours. A value found whose place no form
can tell (a JSON-escaped one holding a surrogate pair) takes its whole
string. Every string in the result is searched but the binary payloads a
Read returns (an image's or a PDF's `file.base64`, a notebook output's
`image.image_data`), megabytes long; image data holds no value as text,
while a PDF's data can hold text the hook does not search. Keys, their
order, types, list lengths and every other value stay exactly as they came, because
Claude Code sends the original when a built-in tool's replacement does not
match its output schema. When nothing is found it prints nothing, and the
result passes untouched.

Claude Code also sends the original output whenever the hook fails, so each
call leaves an owner-only marker, `DIR/<session id>/<tool use id>.json`
(each folder it creates on the way is owner-only too):
`pending` before anything else, then `done` with the count of each name it
kept out once its output is written, or `failed`. A marker holds no value, fragment or decoded form.
A status line refresh, at most once a day, folds each session's markers
older than 7 days into one `.old.json` in its folder (the calls done, those
failed or never finished, and the names kept out with their counts), written
before those markers are removed; the segment and `/weir` read it as they
read the markers, so no session reads differently after, and a marker
younger than that, a call still running included, is never touched.
When the hook cannot redact (an input that is not a PostToolUse input, an
inventory, store or key it cannot use, any error), it marks the call
failed when it can, prints one line on stderr and exits 1. When its output
cannot be written, the marker stays `pending`, read as failed as below.

Claude Code's [hooks reference](https://code.claude.com/docs/en/hooks)
("PostToolUse decision control") says "`updatedToolOutput` only changes
what Claude sees", and that telemetry "also captures the original output
before the hook runs". For a Bash result past roughly 30,000 characters,
its [tools reference](https://code.claude.com/docs/en/tools-reference)
(Bash, "Output limits") says Claude gets "the path of a file saved to the
session directory and truncated past 64 MiB, plus a preview of up to the
first 2,000 characters, and Claude reads or searches the file when it
needs the rest". That saved file, in the session's `tool-results` folder,
holds the original output and is written before the hook runs, and the
result the hook gets names it in `persistedOutputPath`. So the hook also
rewrites that file with the same replacements, through a temporary file
beside it, owner-only (mode 0600), before the call is `done`; a saved file
with no known value is left as it is. It takes the file only at that exact
path, and only as a regular file directly in `<transcript directory>/<session
id>/tool-results/`, neither the file nor those two folders a symbolic link.
A saved file over 256 KiB (262,144 bytes) is not rewritten: searching it
could take longer than the hook's timeout, and Claude Code would then send
the original result too. The hook checks the file's size before it reads
it and leaves a larger file as it is. Nor is one whose search is not done
6 seconds after the hook began: some content (very long tokens, dense
URL-encoded text) takes far longer to search than its size suggests, so
the search stops there: searching the saved file never holds the hook
past the timeout. On Linux and macOS the search runs in a child process,
killed at the deadline; where there is no fork (Windows) it runs in a
thread, and the hook ends its own process as soon as the result is out.
The path must be named exactly as it is, with nothing to normalise (no
`..`, `.` or trailing slash), and the file must still be a regular file
once opened; the hook opens it without waiting, so a FIFO never holds the
hook up.
That, a saved file that is missing, elsewhere, a link, unreadable or
unwritable, or any other error in rewriting it, marks the call `failed`,
so it shows as `possibly not redacted`; the result itself is still
replaced, so the hook prints it, one line on stderr, and exits 0 (on
exit 1 Claude Code would send the original). Each name kept out is
counted once, as often as the saved file or the result held it,
whichever held it more.

With `--markers DIR`, which setup gives them along with the hook, the
segment and the `/weir` report count what the session's calls kept out,
and say `possibly not redacted`, never green, for each covered tool result
that went to the model as the tool returned it, or whose saved output was
not rewritten: a call marked failed, one still `pending` 10 seconds
after it began (Claude Code killed it), and a
result in the session's transcripts whose call has no `done` marker (the
hook never ran or did not finish; Claude Code records a result once the
hook has ended). A failed call (`is_error`) is not one: Claude Code runs
`PostToolUse` after a success only. The report adds `kept out by the
redaction hook:` with each name and count, and `possibly not redacted:`
with the number of such results.

Its limits:

- It doesn't undo a command that already ran: it only changes what the
  model reads afterwards.
- It can't catch a value pasted into the chat; the segment counts it as
  entered.
- A hook failure sends the original output, which is flagged as above.
- An agent that is taken over can switch hooks off.
- Claude Code runs it only after a tool call succeeds: the output of a
  failed call (a command that exits with an error, say) reaches the model
  as it is, and a known value in it counts as entered; `/weir` says it
  entered through a failed tool call and gives a deny rule (below).
- Claude Code saves a large output whole before it runs the hook, which
  then rewrites that saved file: the original is in it for a moment first.
- A saved output over 256 KiB, or one not searched within 6 seconds of the
  call, is not rewritten and keeps the original; the call is flagged as
  above, while the result itself is still replaced.
- A large result of dense URL-encoded text, such as a form body of tens of
  thousands of characters, can take the hook past its timeout: the 6
  second deadline covers the saved file only. Claude Code then sends the
  original, and the call is flagged as above.
- It finds what `weir audit` finds, whole values in the forms above, and
  only in what Claude Code passes it: Claude Code's telemetry keeps the
  original output. A key glued to other characters (`ab` and the key, say)
  is not matched, by the hook or the status line. Nor is one inside the
  binary payloads above.
- A key inside a PDF that Claude reads is not removed. It shows as entered
  when the audit can read it, as unknown when the PDF's text is compressed,
  and not at all when it is written as a PDF hex string or split by
  kerning.
- A WebFetch result is the text Claude Code's own model wrote after reading
  the fetched page with the fetch's prompt ("Prompt to run on the fetched
  content", Claude Code hooks reference, WebFetch input): a key in the page
  has been read by that model before the hook runs, and the hook replaces
  it only where that text repeats it.

## The /weir report

```sh
weir statusline report --inventory REPORT --store STORE --key KEY --session ID [--cache DIR] [--claude-dir DIR] [--markers DIR]
```

It audits the session's files in full (saved tool outputs included) and
prints the segment's words, plain and without `→ /weir` (`weir ⚠ 2
entered · 1 sent`, say), the transcript read, and one block per value
that reached the session, most severe first:

```text
ACME_API_TOKEN (launch env)
  source: launch env, the environment Claude Code starts with
  entered the context: 2 times, first at turn 2: the Bash tool result, <transcript>:5
  sent in a tool call: 1 time, first at turn 3: the Bash tool call, argument command, <transcript>:7
  now sits in: <transcript>; and in the conversation the model received; and wherever the Bash tool call sent it
  advice: rotate it at its issuer; remove ACME_API_TOKEN from the environment Claude Code starts with; delete the session files above once it is rotated
```

A value found in several places lists them all; one a shell startup file
exports says so, and its advice is to take it out of that file. A value
found only in a saved tool output (Claude Code's whole copy of a large
output, `tool-results/*`) never entered the context, but the agent was
given that file's path: its advice is to delete that file. Turn N
starts at the Nth prompt the person typed: a `user` record that is not
`isMeta`, `isCompactSummary` or `isVisibleInTranscriptOnly`, is not a
tool result, holds text, an image or a document, and is not a local slash
command, a shell command run with `!`, their output or an interrupt note
(text starting `<command-name>`, `<command-message>`, `<command-args>`,
`<local-command-…>`, `<bash-input>`, `<bash-stdout>`, `<bash-stderr>` or
`[Request interrupted by user`). A subagent's hit takes the turn of the
tool call that started it, from its sidecar. `--session` takes a plain session id
(else exit 2) and finds `<Claude config dir>/projects/*/<id>.jsonl`.

It judges [the project](#the-project) from the session's project folder
the segment recorded: on each refresh with a project folder in its JSON,
the segment records that folder in `--cache` (the report's `--cache`
defaults to `~/.weir/statusline`, setup's default), in an owner-only file
(mode 0600) that holds only the folder's path. Its name is the first 32
hex characters of an HMAC-SHA256 of the session id under the fingerprint
key, so it names neither the session nor the folder, and one session
never finds another's. A refresh with no project folder removes the
record. The segment and the report so judge the same
folder: the one Claude Code was started in (`workspace.project_dir`, else
`cwd`), never the folder the shell has moved to, and the report never says
`✓ no known key seen` where the segment would not. When the session is
not in the inventory's project, the report ends by saying so and how to
switch the inventory, with the report, store and key it was given, to its
folder:

```text
project: <folder> is not the inventoried project (<inventory's project, or none>), so keys in its files are not known
  to switch the inventory to this folder, run from the shell Claude Code starts from:
    weir inventory --home ~ --project <folder> --process-env --json --store <store> --key <key> > <report>
  the earlier project's keys then stop being counted
```

The last line shows only when the inventory has a project.

Before the segment's first refresh for the session, after one with no
project folder, or with a record that cannot be read, the folder is not
known: the report is never green, says `project: the session's project
folder is not known yet (the status line records it on its first
refresh)`, and gives the same command for the folder it runs in, unless
that folder is in the inventory's project already or cannot be read (it
was removed). The folder it runs in never
decides green: it is the shell's current folder, not the one Claude Code
was started in. A folder that is the home or holds it is never given as
the project, as setup never offers it: its walk would read the whole
home. The report then says `no switch command` instead.

Each folder these lines name, and each inventory file the switch command
names (its report, store and key), is printed under the audit's rule for
a path ([docs/audit.md, "Printing"](audit.md#printing)), with a
credential shape looked for in each segment (between `/` or `\`) rather
than over the whole path: one that holds a value or a run of 6
characters of a value the audit found, or has a segment in a credential
shape, is withheld, and a character it does not print (a line break,
say) reads as a space. A folder such as `/Users/Bob/Dev/ProjX2`, whose
segments joined read as a long random run but none does alone, is
printed. The switch command never names a path in another form
than the rule prints it. A folder printed otherwise (`[withheld]`, or with
a space for such a character): its switch command says to run it in that
folder, with `--project .` in place of the folder. An inventory file
printed otherwise, under a home folder whose name holds part of a key,
say: the switch command is not shown. The report says so and gives the
command to run in the folder with a placeholder for each inventory path:

```text
  no switch command shown: a path in it holds part of a key, reads like one, or holds a character the report does not print. To switch the inventory to this folder, run this in it from the shell Claude Code starts from, with the inventory's own paths in place of the <...> parts:
    weir inventory --home ~ --project . --process-env --json --store <the inventory's store> --key <the inventory's key> > <the inventory's report>
```

A value that entered in the result of a failed tool call (one the
transcript records with `is_error`), which runs no `PostToolUse` hook,
gets a line `entered through a failed tool call:` with its count and first
place, whatever the redaction hook. When the value lives in a file (not
the environment), a `deny rule:` line follows with a settings snippet,
`{"permissions": {"deny": ["Read(~/.aws/credentials)"]}}` say, its path
anchored as Claude Code anchors one: `~/` for a file under the home, and
`//` with the absolute path for any other, a project file included (the
inventory's `./` is its project, but Claude Code would read `./` from the
session's current directory). The rule is given only when the
credential's printed place is not withheld and the exact path the rule
names prints unchanged under the rule for the folders above (the audit's
rule for a path, a credential shape looked for in each segment). The
place itself may still be shown shortened, as a long home path's is,
while the rule names the whole path. No rule is given for a path that
holds a found value or a run of 6 characters of one, has a segment that
looks like a key, or holds a character the report would escape. On
Windows the absolute path takes the POSIX form Claude Code matches,
`C:/Users/alice/proj/.env` as `Read(//c/Users/alice/proj/.env)`: "On
Windows, paths are normalized to POSIX form before matching" (Claude Code
permissions page, "How path patterns match"). It says what the
[Claude Code permissions](https://code.claude.com/docs/en/permissions)
page says such a rule covers: Claude's Read tool (and, best effort, Grep
and Glob) reading that file, and the `cat`, `head`, `tail`, `sed` or `tee`
of it, or a `<` redirect from it, that Claude Code recognizes in a Bash
command. It does not stop a script or program that opens the file itself,
or a command that reads it without naming it; only Claude Code's sandbox
stops those. Nothing rewrites a command.

Setup installs the report as the `/weir` command
(`<Claude config dir>/commands/weir.md`), whose one `` !`…` `` line runs
it with setup's `--cache` for `${CLAUDE_SESSION_ID}`, which Claude Code
puts into the command's text
([skills, "Available string substitutions"](https://code.claude.com/docs/en/slash-commands)).
The report refuses anything but a plain session id, so no other text from
Claude Code, and no folder name, is part of the command, and its
`allowed-tools: Bash(<report> *)` rule matches that line. Claude Code
puts text in for `$0` or `$ARGUMENTS` even inside quotes, so setup
refuses (exit 2, nothing changed) when a path it would write into that
line (the interpreter, `--claude-dir`, `--cache` and the hook's
`--markers` under it, or the inventory, store or key) holds a `$`.

## Setup and undo

```sh
weir statusline setup [--inventory REPORT] [--store STORE] [--key KEY] [--cache DIR] [--claude-dir DIR] [--dry-run]
weir statusline undo [--claude-dir DIR] [--dry-run]
```

`--inventory` defaults to `~/.weir/inventory.json`, `--store` to
`~/.weir/store.json`, `--key` to `~/.weir/fingerprint.key` (the key
[`weir inventory`](inventory.md) makes by default), `--cache` to
`~/.weir/statusline`, and `--claude-dir` to `CLAUDE_CONFIG_DIR`, else
`~/.claude`. Each flag overrides its default. Setup supports POSIX shells
(Linux, macOS) only for now and refuses on Windows (exit 2) before it reads
anything.

So two commands are enough:

```sh
uv tool install weir-scan     # or: pipx install weir-scan
weir statusline setup         # shows the change, applies it only when you type yes
```

**The inventory.** With `--inventory` given, setup uses the three files as
they are, reads no key and computes no HMAC; it refuses (exit 2) when the
`--inventory` file is missing, or when `--store` or `--key` is left to
its default and that default file is missing. With no `--inventory`:

- When there is a report at `~/.weir/inventory.json`, setup uses it as it
  is, never takes it again, and the preview names it with its credential
  count. It refuses (exit 2) when the store or the key that report needs is
  missing.
- When there is none, it is a first setup: setup takes the inventory now,
  of the standard credential locations in the home, the shell startup files
  and the launch environment. Before it does, it names the current folder
  and asks whether to include that project's files: only the exact line
  `yes` includes it (as `weir inventory --project` does, its
  `.weir/reach.yml` map included); any other answer, or none, leaves
  project files out. The home itself, or a folder that holds it (`/`, say),
  is never offered, as its walk would read the whole home: setup says the
  project walk is skipped and goes on with no project. So does a current
  folder that cannot be read (it was removed). The environment of the
  shell running setup is taken as the environment Claude Code starts with,
  so run setup from the shell you start Claude Code from. The preview lists
  the inventory as `weir inventory` lists it, by name, source and location
  only, never a value or a fragment of one, with its counts and the count
  of unknown variables, and the files `yes` writes. It names the project
  folder, or says that no project folder is included, that the status line
  then never shows `✓ no known key seen`, and the command that includes
  one later (`weir inventory --project DIR`, into the files setup
  writes). The key is read
  when there is one (one others can read is refused, below) and otherwise
  made in memory: nothing is written yet.

In both cases, with `--store` and `--key` left to their defaults, the
preview prints the command that refreshes the inventory, the
[`weir inventory`](inventory.md) equivalent of that inventory, with
`--project` and its folder when it has a project and `--no-project` when
not. Run it from the shell you start Claude Code from:

```sh
weir inventory --home ~ --no-project --process-env --json --store ~/.weir/store.json > ~/.weir/inventory.json
```

To switch the project later, run it with `--project DIR` in place of
`--no-project` (or of the project it names):

```sh
weir inventory --home ~ --project DIR --process-env --json --store ~/.weir/store.json > ~/.weir/inventory.json
```

The inventory holds one project at a time: the earlier project's keys
then stop being counted, and a session in that project shows `project not
inventoried` rather than `✓ no known key seen` ([The project](#the-project)).
The status line picks up the new report on its next refresh, so no
second setup is needed.

**Setup** shows the exact change: the segment `statusLine` will run in
`settings.json`, and the new `commands/weir.md`. The new `statusLine`
keeps every key of the old one and runs the segment with the old command
as `--inner`; that command is kept but never shown, as it may hold a
credential, and every other setting is kept. Undo, and setup with
`--inventory` or an existing inventory, read no key and compute no HMAC.
It writes only on the exact line `yes`, `--dry-run` writes nothing at all,
and it refuses when
the settings are not a JSON object, the status line already runs weir, a
different `commands/weir.md` exists, a path for `/weir` holds a `$`, or
it is already set up. On a first
setup it writes the inventory's files first, each owner-only (0600; a new
`~/.weir` is created 0700, and an existing one keeps its own mode): the
key (only when there was none, and never over one made since the preview), the store, the unknown variable names
(`~/.weir/unknown-env.txt`) and the report last, so a report at the
default path always has its store. It keeps the
settings file's bytes beside it as `settings.json.weir-backup`
(owner-only), or, when there is no settings file, leaves an empty
`settings.json.weir-created`, then writes the command file, then the
settings, reading the settings again first and refusing if they changed
since it showed them.
The undo it prints names `--claude-dir`, when given, as an absolute
path, so it runs from any directory.

**The redaction hook.** The preview also shows the hook: the
`hooks.PostToolUse` entry (matcher `Read|Bash|Grep|Glob|WebFetch`, the
hook command, `timeout` 10), and the `statusLine` command and the `/weir`
command file's `allowed-tools` and `!` lines as they are with it, all with
`--markers ~/.weir/statusline/hook-<id>` (under `--cache`). `<id>` is the
first 16 hex characters of the SHA-256 of the Claude config dir's resolved
path, so each config dir's hook keeps its own markers, and undo for one
never removes another's markers. After the `yes` that applies the change,
setup asks `Add the redaction hook too?` and adds the hook only on an
exact `yes` to that; anything else, or no answer,
applies the change without it. When `hooks` is not an object of lists, or
already runs the redaction hook, the preview says the hook cannot be added
and suggests answering no to that question, which installs the status
line alone; a `yes` to it then refuses and changes nothing.

**Undo** shows what it does and, on `yes`, puts back the `statusLine` the
backup holds (or removes it when there was none) while the status line
is still exactly the one setup wrote: the interpreter running `-m weir
statusline` with setup's options, and `--inner` the command from before
setup, when there was one. It takes the redaction hook out of
`hooks.PostToolUse`, and the `PostToolUse` and `hooks` keys when setup
added them. Before it writes the settings it removes the hook's markers
(while the settings still name their folder): the marker and `.old.json`
files in the `--markers` folder its command names (or the status line's,
when the hook was taken out by hand), the `.compacted` file there that
dates the last daily fold, and each folder left empty, never another file.
A weir redaction hook the settings already ran before setup (setup adds
none then) is left as it is, and so are the markers it names. Every other
setting is kept; when nothing else changed it writes the backup's bytes
back (an empty file comes back empty), or removes the settings file when
there was none before setup. It then removes `commands/weir.md` and the
backup or marker. When the status
line changed since setup, or the settings file was removed and there was
one before setup (even an empty one), it refuses and writes and deletes
nothing; its message names the backup, which holds the settings from
before setup, and `commands/weir.md`, to delete once the status line is
put back by hand. With no settings file before setup, a removed
`settings.json` leaves nothing to restore: undo removes `commands/weir.md`
and the marker. A file setup or undo cannot write (a read-only
directory, a full disk) stops it with exit 2 and a message naming that
file and how to finish; `settings.json` is then as it was, or as written
whole. An interrupted setup or undo leaves both usable: running
undo again finishes it, and a first setup stopped before the report was
written takes the inventory again when it is run again (an existing key is
used). Undo leaves `~/.weir` in place: the inventory, store, key and the
checkpoints in setup's `--cache` stay (the hook's markers go, as above). Deleting the checkpoints is safe;
the key, store and report are what `weir audit` and a later setup use.

**The key.** `weir statusline`, `weir statusline report`, `weir inventory`
and `weir audit` read the fingerprint key from a file only its owner can
read, as `weir inventory` creates it (mode 0600): one another
user owns, or that others can read or write, is refused, never repaired.

## What it does not claim

- Everything [`weir audit` does not claim](audit.md#what-the-audit-does-not-claim).
- It knows only the keys in your inventory, as whole values: a key that
  leaves inside a file or by its variable name is not seen, so
  `✓ no known key seen` says no more than that.
- It counts what the session's files hold now, and a value sent by value
  only: a tool call that names a variable (`$TOKEN`) is not counted.
- A rewrite inside the part of a file already read that keeps its end and
  its size is not seen.
- A count is not a guard. Only the redaction hook keeps a credential from
  reaching the agent, and only in the tool results it covers, within its
  limits (above).
- A long record not searched whole within its time bound in three tries
  in a row, each cancelled or out of time, leaves the session partly
  checked rather than counted, where `weir audit` of the whole file counts
  it. Refreshes closer together than its search takes (a search of 0.3 s,
  say, and refreshes 0.3 to 0.6 s apart) can do that to an ordinary
  large tool result, and a slow or busy machine makes it likelier.
- Undo after any other change to the settings writes them back at an
  indent of 2.
