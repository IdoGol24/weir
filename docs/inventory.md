# weir inventory: the credential inventory contract

`weir inventory` finds the credentials an agent could reach and lists them by
**name, source, location and classification only**. It never prints, logs,
caches or stores a value, a fragment of one, a masked form (`prefix...last4`)
or a fingerprint. This document is the interface the guard settings
generator (`weir guard`) and later components build on: the Python API, the
JSON report (`weir-inventory/1`) and the fingerprint store
(`weir-inventory-store/1`).

Schema artifacts, generated from the structs and drift-tested:

- [`packages/weir/schema_artifacts/inventory.v1.schema.json`](../packages/weir/schema_artifacts/inventory.v1.schema.json)
- [`packages/weir/schema_artifacts/inventory-store.v1.schema.json`](../packages/weir/schema_artifacts/inventory-store.v1.schema.json)
- [`docs/inventory-locations.md`](inventory-locations.md): the standard location list, generated

## Running it

```sh
weir inventory --home DIR [--project DIR] [--env-file FILE | --process-env]
               [--gitleaks REPORT]... [--trufflehog REPORT]...
               [--key FILE] [--unknown-list FILE] [--store FILE]
               [--json] [--strict]
```

| option | meaning |
| --- | --- |
| `--home` | **Required.** The home directory to inventory. There is no default, so nothing ever reads a real home by accident. |
| `--project` | Project directory (default `.`). Its `.weir/reach.yml` is the approved map. |
| `--env-file` | The agent's launch environment as `NAME=value` lines (dotenv style: `export ` and one level of matching quotes are stripped, `#` lines skipped), or NUL-separated `env -0` output. |
| `--process-env` | Use this process's own environment as the launch environment. Without either option only shell startup files are read, and the report says so. |
| `--gitleaks` | Import a gitleaks JSON report (`gitleaks detect --report-format json`). Repeatable. Relative `File` paths resolve against the project. |
| `--trufflehog` | Import a trufflehog JSON report (`trufflehog filesystem|git --json`, one result per line, or a JSON array). Repeatable. |
| `--key` | Fingerprint key file, created (mode 0600) when missing. Default `HOME/.weir/fingerprint.key`. |
| `--unknown-list` | Where the unknown environment variable names go. Default `HOME/.weir/unknown-env.txt`. Always written, one `NAME<TAB>location` per line, names only. |
| `--store` | Write the fingerprint store here (keyed fingerprints plus offsets, mode 0600). Nothing is stored without it. |
| `--json` | Print the `weir-inventory/1` report instead of the names-only text. |
| `--strict` | Exit 1 when any environment variable is unknown. |

Exit codes: `0` listed (finding credentials is not a failure); `1` only with
`--strict` and at least one unknown variable; `2` an input cannot be used
(missing home or project, unreadable env file, malformed scanner report,
invalid map, unusable key). An error message names the input, never content
read from it.

## The four sources

1. **Standard locations** (`standard_location`). A fixed, versioned list of
   credential files under the home: `~/.aws`, Google's application default
   credentials, `~/.npmrc`, `~/.kube/config`, `~/.docker/config.json`,
   `~/.netrc`, git credentials, gh, and more
   ([full list](inventory-locations.md)). Each entry names the fields that
   are the credential in its format, and the environment variables that move
   the file (`AWS_SHARED_CREDENTIALS_FILE`, `DOCKER_CONFIG`, `KUBECONFIG`).
   Overrides are read from the launch environment being inventoried and
   resolved against the given home; the default path is checked as well. A
   standard file that weir cannot read or parse is still reported, as a
   whole-file credential (`value_state: absent`) plus a `not_scanned` entry.
2. **Project files** (`project_scan`). Imported gitleaks and trufflehog
   results, plus Weir's own detectors over every project file: the catalog's
   key-shaped classes judged by their eligibility patterns, the catalog's
   `credential_field` assignment class (with the 0.4.1 escape-boundary fix),
   an assignment detector for `key = value`, `key: value` and JSON
   `"key": "value"` whose key name suggests a secret, and standalone shapes
   (JWT, URL with a password, PEM private key). Hits covering the same bytes
   merge into one credential whose `detectors` lists every finder; the same
   value twice in one file is one credential with two offsets. Dependency
   directories (`node_modules`, `.venv`, ...) are skipped whole and listed
   under `not_scanned`, as are binary, oversized (> 2 MiB) and unreadable
   files. A symlinked file is followed; a symlinked directory is listed as
   `symlinked_dir` and not followed. `.git` and `.weir` are not project
   files.
3. **Launch environment** (`environment`). The env file or process
   environment, plus every exported assignment in the shell startup files
   (`~/.bashrc`, `~/.zshrc`, `~/.profile`, fish, csh; see the list). A
   startup file that re-exports a variable is its own record, because an
   environment block is undone by a startup file the agent can read. An
   assignment from a shell expansion (`export TOKEN=$(pass show x)`) is a
   credential by name with `value_state: dynamic`. A secret assigned in a
   startup file but never exported is still a credential, since the file is
   readable; an unexported variable that is not a secret is not part of the
   environment and is neither counted nor listed.
4. **Approved map** (`map`): `<project>/.weir/reach.yml`, where a person
   declares what discovery cannot know. Strict schema: an unknown key is an
   error (exit 2), so a typo never reads as an approval.

   ```yaml
   version: 1
   credentials:
     - path: config/creds.go      # project-relative, ~/home-relative or absolute
       name: PAYMENTS_SIGNING_KEY # optional label; defaults to the field or file name
       field: signing_key         # optional: only the value assigned to this key
   env:
     fine: [BUILD_TAG, CI_RUNNER] # unknown variables a person marked fine
   ```

   An entry without `field` makes the whole file a credential
   (`value_state: absent`). A path that does not exist is listed under
   `not_scanned` as `missing`. `env.fine` moves matching *unknown* variables
   from `env_unknown` to `env_fine`; it never demotes a secret.

## Classification

Environment variables (and the fields of standard files) are judged by
local, deterministic checks, in this order:

1. **Shape**: the value has a credential shape (a catalog key shape such as
   `ghp_...` or `AKIA...` that clears its eligibility pattern, a JWT, a URL
   with a password, a PEM private key) -> secret, reason `shape`.
2. **Not a secret**: the value is empty, a number, a boolean
   (`true/false/yes/no/on/off`), a path (absolute, `~`, `./`, `../`, a drive
   letter, `$HOME/...`, or a `PATH`-style list of these) or a plain hostname
   (dotted name with an alphabetic top label, `localhost`, IPv4, optional
   port). A path segment of 20+ characters mixing upper case, lower case
   and digits with no separator is key material, not a directory, so an AWS
   secret key starting with `/` is not waved through.
3. **Name**: the name suggests a secret -> secret, reason `name`. A name is
   split into words (`ACME_API_KEY`, `clientSecret`, `_authToken`); it
   suggests a secret when a word is one of SECRET, TOKEN, PASSWORD, PASSWD,
   PASS, PWD, PASSPHRASE, CREDENTIAL(S), CREDS, APIKEY, AUTHTOKEN, JWT,
   BEARER, COOKIE, DSN, PRIVATEKEY, or when KEY follows a qualifier such as
   API, ACCESS, SECRET, PRIVATE, CLIENT, SIGNING, or ends the name
   (`STRIPE_KEY`) without PUBLIC or PUBLISHABLE before it.
4. Anything else is **unknown**: a count on screen, the full list (names
   only) in the unknown-list file and in the JSON report, never a failure
   unless `--strict`, and markable as fine in the map.

Project-file assignments use the name rule with a minimum value length of 8
(the catalog's `credential_field` floor) and reject placeholders
(`${VAR}`, `<your-token>`, `{{ x }}`, `***`, `changeme`, ...) and, in source
code, unquoted identifiers and calls (`password = get_password()`).

A name or scope parsed out of a file is untrusted. It is flattened to one
printable line, and one that itself has a credential shape is replaced with
`[withheld: credential-shaped]`.

## Files ignored by git

Ignoring a file is not coverage. A project credential in a file a
`.gitignore` rule covers (global excludes, `.git/info/exclude`, every
`.gitignore` from the root down, gitignore(5) semantics, computed locally)
carries `git_ignored: true`, and the file is listed in `git_ignored` with
its per-route effect:

| route | status | why |
| --- | --- | --- |
| `grep_tool` | hidden | Claude Code's Grep skips gitignored files when it searches a directory; given the file's path it still reads it |
| `read_tool` | reachable | `.gitignore` has no effect on Read |
| `cat` | reachable | shell commands ignore `.gitignore` |
| `grep_r` | reachable | `grep -r` ignores `.gitignore` |

## Values never leave the process

- The report (`Inventory`) and every struct in it are value-free by
  construction: no field can hold a value.
- The store holds, per value, a **keyed fingerprint**: lowercase hex
  HMAC-SHA256 of the UTF-8 value under a 32-byte local key
  (`fingerprint_v: 1`), plus the absolute path and `[start, end)` byte
  offsets of each occurrence. Never a value, a fragment or an unkeyed hash.
  The same key and value always give the same fingerprint, so a changed
  fingerprint means a rotated value.
- The values themselves exist only in process memory, in
  `InventoryResult.values` (`KnownValues`), for an in-process consumer such
  as the redaction hook. Its repr is a count, it refuses to pickle, and it is
  not a msgspec struct, so it cannot be encoded.

## Python API

```python
from pathlib import Path
from weir.inventory import InventoryInputs, take_inventory, default_key_path

result = take_inventory(InventoryInputs(
    home=Path("/fake/home"),            # required, no default
    project=Path("/fake/home/work/proj"),
    key_path=default_key_path(Path("/fake/home")),
    env_file=Path("/fake/launch.env"),  # or process_env=dict(...); at most one
    gitleaks_reports=[...],
    trufflehog_reports=[...],
))
result.report   # weir.inventory.Inventory: value-free, JSON via encode_report()
result.store    # weir.inventory.Store: keyed fingerprints plus offsets
result.values   # weir.inventory.KnownValues: id -> value, in memory only
```

`take_inventory` raises `InventoryInputError` for an unusable input. It is
deterministic: the same inputs and key give byte-identical
`encode_report()` and `encode_store()` output. The key only affects the
store; the report does not depend on it.

What a settings generator reads from `report`:

| need | where |
| --- | --- |
| credential files to deny (Read rules, sandbox read blocks) | `credentials[].location` with `kind: file`: `path` (absolute) and `display` (`~/...` under the home, `./...` under the project, absolute elsewhere, forward slashes) |
| environment secrets to mask or deny | `credentials[]` with `source: environment` and `location.kind: launch_env`: `name` |
| startup files that re-export a secret | `credentials[]` with `source: environment` and `location.kind: file` |
| files whose `.gitignore` entry is no protection | `git_ignored[]` |
| what was not looked at | `not_scanned[]`, `inputs.env_source` (`none` = no launch environment given) |
| unknown variables and the ones marked fine | `env_unknown[]`, `env_fine[]` (names and locations only) |

## The JSON report (`weir-inventory/1`)

`weir inventory --json` prints `encode_report(report)`: indented JSON,
fields in schema order, lists sorted. Top level:

| field | type | meaning |
| --- | --- | --- |
| `schema` | string | `"weir-inventory/1"` |
| `inputs` | object | `home`, `project` (absolute), `env_source` (`file` / `process` / `none`), `env_file`, `gitleaks_reports`, `trufflehog_reports`, `map_file` (or null), `location_list_version` |
| `counts` | object | `credentials`, one count per source (`standard_location`, `project_scan`, `environment`, `map`), `env_not_secret`, `env_unknown`, `env_fine`, `git_ignored_files`, `not_scanned` |
| `credentials` | array | sorted by source, location, line, name, scope |
| `env_unknown` | array | `{name, location}`, sorted |
| `env_fine` | array | `{name, location}`, sorted |
| `git_ignored` | array | `{display, path, routes: [{route, status, note}]}` |
| `not_scanned` | array | `{display, reason, path}`; reason is `binary`, `too_large`, `unreadable`, `undecodable`, `vendored_dir`, `symlinked_dir` or `missing` |

A credential:

| field | type | meaning |
| --- | --- | --- |
| `id` | string | 16 base32 characters of a digest over the record's identity (source, displayed location, line, name, scope, commit), never over the value. Joins the record to the store and to `KnownValues`. |
| `name` | string | field or variable name (`aws_secret_access_key`, `ACME_API_KEY`), catalog class (`github_token`), shape (`jwt`) or scanner rule (`gitleaks:generic-api-key`) |
| `source` | string | `standard_location`, `project_scan`, `environment`, `map` |
| `reason` | string | `location`, `name`, `shape`, `scanner`, `map` |
| `location` | object | `kind` (`file` / `launch_env`), `display`, `path` (absolute or null), `line` (1-based or null), `commit` (scanner results from git history) |
| `value_state` | string | `literal` (value read, fingerprinted), `dynamic` (shell expansion), `absent` (whole-file credential, value not extracted) |
| `detectors` | array | every detector that found it, sorted: `location:<id>`, `catalog:<class>`, `assignment`, `shape:<shape>`, `launch_env`, `startup_file`, `gitleaks:<rule>`, `trufflehog:<detector>`, `map` |
| `scope` | string or null | profile, section, host or JSON path (`default`, `github.com`, `mcpServers.acme-search.env`) |
| `git_ignored` | boolean | a `.gitignore` rule covers the file |

## The store (`weir-inventory-store/1`)

`{"schema": "weir-inventory-store/1", "records": [...]}`, records sorted by
`credential_id`, each `{credential_id, fingerprint, fingerprint_v, path,
offsets}`. `path` is null for the process environment; `offsets` is empty
when a value's position is unknown (a scanner result whose file moved, git
history).

## Versioning

- `schema` changes only with an incompatible report change; additive fields
  keep `weir-inventory/1`.
- `location_list_version` bumps whenever the standard list, the startup file
  list, a format or a field list changes.
- `fingerprint_v` bumps whenever the fingerprint input or algorithm changes;
  it is never a silent migration.
