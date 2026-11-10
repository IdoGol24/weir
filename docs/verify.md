# weir-run verify: check a credential swap or sandbox, and sign the result

> **The contract.** `weir-run verify` and `weir-run predicate` (in
> `packages/weir-run/src/weir_run/`) implement this document; where code and
> text disagree, one of them is a bug.

A credential swap keeps a real key out of an agent's reach: the agent holds
a stand-in, and a proxy or sandbox puts the real key back only on requests
to the key's own provider. `weir-run verify` proves, with a planted fake key,
whether a named swap does that, and writes an evidence record of the
verdict. `weir-run predicate` turns the record into an in-toto test result,
and a reusable workflow signs it, so a deployment can check it before the
image runs.

## Running it

```sh
weir-run verify --target iron-proxy --evidence weir-verify-evidence.json \
  --image-digest sha256:<64 hex>
```

| flag | meaning |
| --- | --- |
| `--target` | the credential swap or sandbox to check: `iron-proxy` |
| `--target-command` | the target's executable; default its own command on `PATH` |
| `--evidence` | write the evidence record here |
| `--image-digest` | the digest of the image whose target binary was checked, kept in the record; it only names the image |
| `--weir` | the `weir` executable to judge with |

Exit `0` clean, `1` a finding (a leak or an unmediated tool call), `3`
incomplete, `2` for a usage error or a failure of the run itself, as for
`weir-run run` ([canary.md](canary.md#exit-codes)).
It needs Linux with unprivileged user namespaces: the run is always
[isolated](canary.md#network-isolation), and a run that cannot be is
incomplete. Values are fresh fake keys; no real key is read or sent.

## What it checks

One placement, `env.ANTHROPIC_API_KEY`, a fake Anthropic-shaped key whose
own provider is the local mock's model API, on `127.0.0.1`. The target holds
it. A built-in probe stands in for the agent and exposes whatever its
`ANTHROPIC_API_KEY` holds to every sink, through the target's proxy:

| sink | what reaches it | a hit there |
| --- | --- | --- |
| `model` | a Messages API request to `127.0.0.1`: the key in `x-api-key` and in the prompt | the key anywhere but `x-api-key` |
| `telemetry` | an OTLP/JSON span with the key in an attribute, sent to `localhost`, and anything the target exports itself | the key in any export |
| `console` | the probe's own stdout and stderr, and the target's log | the key in either stream |
| `outbound` | a request to the program's own API at `localhost`, the key in a header and the body | the key anywhere in it |

Under a working target the probe holds only a stand-in, the target puts the
key in the `x-api-key` header of the model request (the placement is
`exercised`), and nothing else carries it. The judge is `weir canary judge`,
with every encoded form it matches. verify prints each flow's output with
every match of the key replaced, and withholds any line that holds 6
characters in a row of the key's random part, as `weir-run run` does.

A sink's verdict is `leak` when it holds a hit, `not_reached` when nothing
reached it, and `clean` otherwise. The run is `leak` when any sink leaks,
otherwise `unmediated-tool-call` when the run's mock saw a tool execute
that no model request asked for ([canary.md](canary.md#tool-calls)); both
are findings and fail the run. verify's own probe runs no tool and its
mock declares no tool endpoint, so the current target never reaches this
verdict; the record carries it so that the mock's own check, the one
`weir-run run` makes, fails any verify run that does. The run is
`clean` only when every sink was reached and is clean, the key was
exercised, the run was isolated with no direct connection attempt and no
reason below holds, and `incomplete` otherwise. Never a false clean: what the run could not check is
incomplete.

| reason | when |
| --- | --- |
| `target_missing` | the target's executable was not found, or its version could not be read; no flow runs |
| `sink_not_reached` | a sink received nothing |
| `judge_not_clean` | the record's fields are clean but the judge's own verdict is not |
| `judge_other` | the judge gave a reason this verify does not know, as a newer judge may |
| `value_fragment` | a captured file or request holds 6 characters in a row of the key's random part outside every match of the whole key: a slice of the key, which the judge does not match |

The judge's reasons, such as `flow_not_ok` when the target or the probe
failed, are as in [canary.md](canary.md#coverage-states).

### Targets

- **`iron-proxy`**: runs beside the probe, with a config whose `secrets`
  transform swaps the stand-in for the key in `x-api-key` on `127.0.0.1`.

A target is a name, its command, and the flow that runs the probe through
it, so other credential swaps and sandboxes can be added. weir's own tests
drive the target against a small local fake, so they need no real tool.

## The evidence record (`weir-verify-evidence/2`)

A stable contract for other tools: fields are never removed or changed
within a schema version; a change makes a new one. A
target, tool or placement name is a pattern, not a list, so adding a target
or a tool does not change the schema version; verify writes only the
names it knows. The
JSON Schema is
[`packages/weir-run/schema_artifacts/weir-verify-evidence.v2.schema.json`](../packages/weir-run/schema_artifacts/weir-verify-evidence.v2.schema.json),
generated from the record's structs and drift-tested, with
`additionalProperties: false` on every object.

| field | type | meaning |
| --- | --- | --- |
| `schema` | string | `"weir-verify-evidence/2"` |
| `target` | string | the target's name, such as `iron-proxy`: `^[a-z0-9][a-z0-9.-]{0,39}$` |
| `tools` | array | `{name, version}` for `weir-run`, `weir-scan` and the target, when its version was read; `name` as `target` |
| `manifest_sha256` | string | SHA-256 of what was checked: the target, the placement, the sinks and the probe's code |
| `image_digest` | string or null | `sha256:<64 hex>` from `--image-digest` |
| `verdict` | string | `clean`, `leak`, `unmediated-tool-call` or `incomplete` |
| `findings` | array | `{type, reason, count}`, sorted by `type` and `reason`: one `leak` entry when any sink holds a hit, `reason` null and `count` the sinks' hits; one `unmediated-tool-call` entry per reason, `not_issued` or `tool_mismatch` ([canary.md](canary.md#tool-calls)), `count` the tool calls. Empty when the verdict is `clean` or `incomplete` |
| `placements` | array | `{id, state, hits}`; `id` is `env.<VARIABLE>`, such as `env.ANTHROPIC_API_KEY`; `state` is `leaked`, `exercised` or `not_exercised` |
| `sinks` | array | `{name, verdict, received, hits}` for `console`, `model`, `outbound` and `telemetry`, in that order; `received` counts the requests the mock served for a request sink and the non-empty output streams for `console` |
| `incomplete` | array | `{reason, count}`, by reason, from a fixed list |
| `network` | object | `isolated`, and `direct_attempts`, the connections the isolation blocked |

weir-run 0.3.0 wrote `weir-verify-evidence/1`: the same record
with `schema` `"weir-verify-evidence/1"`, no `findings`, and the verdict
`clean`, `leak` or `incomplete`. Its JSON Schema is
[`weir-verify-evidence.v1.schema.json`](../packages/weir-run/schema_artifacts/weir-verify-evidence.v1.schema.json),
also drift-tested and unchanged. `weir-run predicate` still accepts a v1
record and makes the same predicate for it as weir-run 0.3.0 did.

verify writes only fixed names, verdicts, counts, digests and versions,
never a value, a fragment of one, a prompt or a program's output. A name
field is checked against a pattern, not a list, so the schema alone does
not prove a name holds no value: a record is value-free because verify
made it. Its signature proves only which repository's workflow handed it
over (see [The signed result](#the-signed-result)).

## The signed result

`weir-run predicate --evidence FILE [--url URL]` prints the
[in-toto test-result](https://github.com/in-toto/attestation/blob/main/spec/predicates/test-result.md)
predicate (`https://in-toto.io/attestation/test-result/v0.1`) for a record:

- `result`: `PASSED` for `clean`; `FAILED` for a finding (`leak`,
  `unmediated-tool-call`) and for `incomplete`. Never `WARNED`.
- `configuration`: the manifest by its digest, then the record by the
  SHA-256 of its bytes, with the record itself as its `annotations`.
- `passedTests` and `failedTests`: `sink:<name>` per sink, and in
  `failedTests` `finding:<type>` per finding type, such as
  `finding:unmediated-tool-call`, and `incomplete:<reason>` per reason. The
  finding's reason is a field of the record in `annotations`.

It refuses (exit 2) a record that breaks the schema, whose sink verdicts do
not match their counts, whose findings do not match its sinks, or whose
verdict its fields do not support.

A run with an unmediated tool call can never produce a `PASSED` result, so
it never satisfies a deployment check that requires `PASSED`. Its `FAILED`
result is still signed by the workflow below, exactly as a leak's is: a
signature records what the run found, failures included.

The reusable workflow
[`.github/workflows/verify-attest.yml`](../.github/workflows/verify-attest.yml)
signs it with `actions/attest`. The job that runs verify gets no `id-token`
or `attestations` permission and hands over only the record; the signing
job checks out weir at the workflow's own commit, refuses an invalid
record, and attests the record's image digest. The caller grants every
permission the signing job asks for, `packages: write` included even
without `push-to-registry`, since a called workflow gets no more than its
caller grants. Pin it by full commit:

```yaml
jobs:
  verify:
    needs: build # the job that built and pushed the image
    runs-on: ubuntu-latest
    permissions:
      contents: read
    steps:
      # weir-run isolates the run in an unprivileged network namespace.
      - run: sudo sysctl -w kernel.apparmor_restrict_unprivileged_userns=0
      - run: pipx install weir-run # and the target binary, copied from the image under test
      - run: weir-run verify --target iron-proxy --image-digest "$DIGEST" --evidence weir-verify-evidence.json
        env:
          DIGEST: ${{ needs.build.outputs.digest }}
      - uses: actions/upload-artifact@cf430e030ddbb5b0abf93d22962f4752f3646cd9 # v7.0.2
        if: ${{ !cancelled() }}
        with:
          name: weir-verify-evidence
          path: weir-verify-evidence.json
          if-no-files-found: error
  sign:
    needs: verify
    if: ${{ !cancelled() }} # a FAILED result is signed too
    permissions:
      contents: read
      id-token: write
      attestations: write
      packages: write # asked for by the signing job, with or without push-to-registry
    uses: ralis-ai/weir/.github/workflows/verify-attest.yml@<full commit SHA>
    with:
      evidence-artifact: weir-verify-evidence
      subject-name: ghcr.io/example-org/agent
      push-to-registry: true
```

`push-to-registry` stores the attestation beside the image, which the
Kyverno example needs. It logs in to `ghcr.io` with the job's token and
refuses a `subject-name` anywhere else. The signing certificate names the
signing workflow, which any repository can call: a check must also tie the
result to your repository, by the registry it is stored in or by the
certificate's source repository, as both examples do. Attestations on a
private repository need GitHub Enterprise Cloud.

The signing job checks only the record's shape and consistency, not how it
was made, so the signed statement proves that the calling repository's own
workflow run produced the record. A deployment check that trusts the result
therefore trusts that repository's workflow.

## Checking it before a deployment

Both are **examples**: adapt the names, and test them in your own setup.

**Kyverno**, an example `ImageValidatingPolicy` in CEL. It checks every
container and init container image under the policy's image references.
This example is safe only when an image digest carries one verify result.
If the same digest is verified again, for example by re-running the
workflow, it gets a second signed result, and Kyverno may check an earlier
`PASSED` result instead of a later `FAILED` one, because it reads whichever
attestation the registry lists, not the newest. So verify a new digest
rather than re-verify the same one. Where a digest can carry repeated
results, use the pattern of the ECS hook below, which checks the newest
result. For an in-toto attestation `extractPayload` returns the whole
statement, so the result is under `predicate`. The attestation must be in
the image's registry.

```yaml
apiVersion: policies.kyverno.io/v1
kind: ImageValidatingPolicy
metadata:
  name: require-weir-verify-passed
spec:
  validationActions: [Deny]
  matchConstraints:
    resourceRules:
      - apiGroups: [""]
        apiVersions: [v1]
        operations: [CREATE, UPDATE]
        resources: [pods]
  matchImageReferences:
    - glob: ghcr.io/example-org/agent*
  attestors:
    - name: weir
      cosign:
        keyless:
          identities:
            - issuer: https://token.actions.githubusercontent.com
              subjectRegExp: '^https://github\.com/ralis-ai/weir/\.github/workflows/verify-attest\.yml@[0-9a-f]{40}$'
        ctlog:
          url: https://rekor.sigstore.dev
  attestations:
    - name: verify
      intoto:
        type: https://in-toto.io/attestation/test-result/v0.1
  validations:
    # Images outside matchImageReferences are not verified, so check only those.
    - expression: >-
        (images.containers + images.initContainers)
        .filter(image, image.startsWith('ghcr.io/example-org/agent'))
        .all(image,
          verifyAttestationSignatures(image, attestations.verify, [attestors.weir]) > 0 &&
          extractPayload(image, attestations.verify).predicate.result == 'PASSED')
      message: no signed, PASSED weir-run verify result for this image
```

**Amazon ECS**, a deployment lifecycle hook: a Lambda function, registered
at `PRE_SCALE_UP`, that lets the deployment go ahead only when the newest
signed result for each checked image, by its transparency-log time, is
`PASSED`; see the ECS guide to
[lifecycle hooks](https://docs.aws.amazon.com/AmazonECS/latest/developerguide/deployment-lifecycle-hooks.html).
Its event names the service revision
by ARN, not the image, so it resolves each image digest first. The API
hands over each signed bundle as a snappy-compressed file at a pre-signed
`bundle_url`, fetched without the GitHub token. Package it with
[`sigstore`](https://pypi.org/project/sigstore/) and
[`python-snappy`](https://pypi.org/project/python-snappy/).

```python
import json
import os
import re
import urllib.error
import urllib.request

import boto3
import snappy
from sigstore.errors import VerificationError
from sigstore.models import Bundle
from sigstore.verify import Verifier, policy

# The owner/repo whose workflow ran verify, and the signing workflow, as
# https://github.com/ralis-ai/weir/.github/workflows/verify-attest.yml@<sha>
REPO = os.environ["CALLER_REPOSITORY"]
SIGNER = os.environ["SIGNER_WORKFLOW"]
TOKEN = os.environ.get("GITHUB_TOKEN")  # a public repository needs none
TEST_RESULT = "https://in-toto.io/attestation/test-result/v0.1"
ISSUER = "https://token.actions.githubusercontent.com"
ecs = boto3.client("ecs")
verifier = Verifier.production()
signed_by = policy.AllOf(
    [policy.Identity(identity=SIGNER, issuer=ISSUER), policy.GitHubWorkflowRepository(REPO)]
)


def get(url, headers=None):
    request = urllib.request.Request(url, headers=headers or {})
    with urllib.request.urlopen(request, timeout=20) as r:
        return r.read(), r.headers.get("Link", "")


def attestations(digest):
    """Every attestation for digest, page by page. The API answers 404 for
    a digest with none, which is no result; any other error raises."""
    url = f"https://api.github.com/repos/{REPO}/attestations/{digest}"
    url += f"?predicate_type={TEST_RESULT}&per_page=100"
    headers = {"Authorization": f"Bearer {TOKEN}"} if TOKEN else {}
    try:
        body, link = get(url, headers)
    except urllib.error.HTTPError as error:
        if error.code == 404:
            return
        raise
    while True:
        yield from json.loads(body).get("attestations", [])
        following = re.search(r'<([^>]+)>;\s*rel="next"', link)
        if not following:
            return
        body, link = get(following.group(1), headers)


def newest_result(digest):
    """The result of the newest verified test result for digest, or None.
    Only a bundle another signer made is skipped: any other error raises,
    so the hook fails rather than pass over a newer result."""
    found = []
    for item in attestations(digest):
        raw = item.get("bundle") or json.loads(snappy.decompress(get(item["bundle_url"])[0]))
        bundle = Bundle.from_json(json.dumps(raw))
        try:
            _, payload = verifier.verify_dsse(bundle, signed_by)
        except VerificationError:
            continue
        statement = json.loads(payload)
        subjects = {s["digest"].get("sha256") for s in statement["subject"]}
        if statement["predicateType"] == TEST_RESULT and digest.removeprefix("sha256:") in subjects:
            (entry,) = raw["verificationMaterial"]["tlogEntries"]
            found.append((int(entry["integratedTime"]), statement["predicate"]["result"]))
    return max(found, key=lambda f: f[0])[1] if found else None


def handler(event, context):
    arn = event["executionDetails"]["targetServiceRevisionArn"]
    revision = ecs.describe_service_revisions(serviceRevisionArns=[arn])["serviceRevisions"][0]
    names = {n for n in event.get("hookDetails", {}).get("containers", "").split(",") if n}
    images = [c for c in revision["containerImages"] if not names or c["containerName"] in names]
    ok = bool(images) and all(newest_result(c["imageDigest"]) == "PASSED" for c in images)
    return {"hookStatus": "SUCCEEDED" if ok else "FAILED"}
```

Name the containers to check in the hook's `hookDetails`, as
`{"containers": "agent"}`; without it, every container's image must have a
result.

## Limits

- One placement, an Anthropic key in an environment variable, and the
  target above. User flows, file credentials and other targets are not
  covered.
- Linux only, since the run must be isolated.
- verify checks the target binary it runs on the runner, in the
  configuration it generates; `--image-digest` only names an image. Run it
  with the target binary from that image, so the result speaks for it. It
  says nothing about a configuration of your own.
