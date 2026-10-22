# The Weir GitHub Action

Runs a [weir-run](https://github.com/IdoGol24/weir/tree/main/packages/weir-run)
config in a pull request job and posts the verdict on the pull request: one
comment, updated in place on every re-run. The job fails on a leak or an
incomplete run and passes on a clean one.

## Use it

One step, after the steps that check out your code and install your project:

```yaml
- uses: IdoGol24/weir@<ref>   # a release tag, or better its full commit SHA
```

A whole workflow:

```yaml
name: leak check
on: pull_request

permissions:
  contents: read
  pull-requests: write          # the comment; nothing else is written

# One run per pull request at a time, so an older commit's run cannot
# overwrite a newer one's verdict in the comment.
concurrency:
  group: weir-${{ github.event.pull_request.number }}
  cancel-in-progress: true

jobs:
  weir:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          persist-credentials: false   # keep the job token out of the checkout
      - uses: actions/setup-python@v6
        with:
          python-version: "3.12"
      - run: pip install -e .          # your project, so its flows can import it
      - uses: IdoGol24/weir@<ref>
        with:
          config: canary.toml
          require-isolation: true
```

The config is the one `weir-run run --config` takes; the
[weir-run README](https://github.com/IdoGol24/weir/tree/main/packages/weir-run#the-config)
describes it. Use `on: pull_request`, never `pull_request_target` with the
pull request's code: that would run untrusted code in a job whose token can
write.

## What it does

1. On a GitHub-hosted Linux runner, it allows unprivileged user
   namespaces, which GitHub's Ubuntu images restrict, so weir-run can run
   the flows where the only network is loopback. That machine lasts one
   job. It never changes this setting on a self-hosted runner.
2. It installs weir-scan and weir-run with pip, each at one exact version,
   wheels only.
3. It runs `weir-run run --config <config> --report <file>`, with
   `--require-isolation` when asked. The job log shows weir-run's output
   as usual: each flow's output with every planted value replaced, then
   the report.
4. In a separate step, the only one of its own steps that is given the
   job's token, it writes
   the verdict to the job's step summary and, on a pull request, to its
   comment, then ends with the verdict's exit code.

## Inputs

| input | default | what it is |
| --- | --- | --- |
| `config` | `canary.toml` | the weir-run config, relative to the workspace |
| `require-isolation` | `false` | `true`: a run whose flows could not be isolated from the network is incomplete |
| `comment` | `true` | `false`: no comment, only the step summary |
| `comment-key` | the config path | tells two checks' comments apart on one pull request, such as a matrix's jobs |
| `python-version` | none | set up this Python first, with actions/setup-python; by default the job's own Python is used |
| `weir-scan-version` | the version at the action's ref | the exact weir-scan version |
| `weir-run-version` | the version at the action's ref | the exact weir-run version |

**Python.** weir-run is installed into the job's Python (`python`, else
`python3`), so a flow's `{python}` is the interpreter your project is
installed in. It needs Python 3.12 or later and a pip that may install,
such as the one actions/setup-python sets up or a virtual environment's.
The system Python on GitHub's Ubuntu images refuses pip installs, so set
up Python first or pass `python-version`.

**Versions.** By default the action installs the weir-scan and weir-run
versions recorded at the ref you use, so pinning the action pins them too.
Pin a release tag or its commit SHA. Between releases, the versions
recorded on `main` are those of the last release, while its code may be
newer: when the recorded weir-run needs a newer weir-scan than the one
recorded, the action stops with an error instead of installing older code
than it documents. A version input takes one exact version, such as
`0.6.0`, never a range.

## Outputs

| output | what it is |
| --- | --- |
| `result` | `clean`, `leak`, `incomplete` or `error` |
| `exit-code` | weir-run's exit code |
| `report` | the path of the judge's JSON report (`canary-report/1`), when the run reached a verdict |

The report holds no value and may be uploaded as an artifact.

## The verdict

| weir-run exit | result | the job |
| --- | --- | --- |
| `0` | `clean` | passes |
| `1` | `leak` | fails |
| `3` | `incomplete` | fails |
| `2` | `error` | fails: a usage, configuration or runner error |

Any other exit code is an `error`, and so is an exit code the report's
`result:` line does not confirm. A Python that cannot import weir-run exits
1, which is no leak.

## The comment

The comment starts with a hidden marker naming its `comment-key`. On a
re-run the action finds the comment that the Actions bot wrote with that
marker and updates it, so each check keeps one comment. A comment anyone
else wrote is never touched, whatever it holds.

It shows the result, then the report's own lines in a code block: each
`LEAK` line, the not-exercised placements, the blocked destinations, the
incomplete reasons, and the coverage, network and result lines. Only lines
of the judge's report are shown, and they name placements, locations and
sinks, never a value or a fragment of one. A long report is cut after 60
lines, the coverage, network and result lines kept, and the job log has the
rest. An error shows weir-run's exit code and no report. The footer names
the config, the pull request's head commit and the job log. On a
`pull_request` event GitHub checks out the merge of that head into the base
branch, so the tree judged is that merge commit.

## Permissions and the token

- The comment needs `pull-requests: write`. Without it, or on a pull
  request from a fork, whose token is read-only, the action warns that no
  comment was posted, and the verdict and the job's result stand; the step
  summary still has the verdict.
- The action uses the job's own `GITHUB_TOKEN` and no other secret. Of
  the action's own steps only the one that posts the comment is given it,
  after the flows have run. With `python-version` set,
  actions/setup-python also receives the job token through its own `token`
  input default, and exits before the check step. So no process holds the
  token while the flows run. Every flow also starts from an empty
  environment.
- It makes no request but the comment's, to the GitHub API the job runs
  against, the PyPI install and, with `python-version`, the download
  actions/setup-python makes.

## Limits

- Its steps have been run on Linux, outside GitHub's own runner, against
  a stand-in for the GitHub API. macOS and Windows runners are untested,
  and there the flows are never isolated from the network, so
  `require-isolation: true` makes every run incomplete.
- pip installs weir-scan and weir-run at exact versions; their own
  dependencies, such as click and protobuf, are resolved by pip within the
  ranges those packages declare.
