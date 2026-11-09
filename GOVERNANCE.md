# Governance

This file describes how Weir is run today. Weir is a small open source
project with a single maintainer.

## Maintainer

Weir has one maintainer, the GitHub account
[@IdoGol24](https://github.com/IdoGol24). The maintainer reviews and merges
changes, triages issues, cuts releases and decides the project's direction.

## Security lead

The security lead is [@IdoGol24](https://github.com/IdoGol24). Security
reports follow the private route in [SECURITY.md](SECURITY.md), not public
issues.

## How decisions are made

The maintainer makes decisions. Proposals and disagreements go in an issue or
on the pull request, in the open, and the maintainer decides.

## How changes land

Every change lands through a pull request against `main`, or against a
`release/**` branch for a patch release. CI runs the tests, lint, type check
and import contracts on Linux and Windows for each pull request (see
[CONTRIBUTING.md](CONTRIBUTING.md)). The maintainer reviews the change and
merges it once CI is green.

## Becoming a maintainer

There is no fixed process yet. A regular contributor whose changes have been
merged can ask in an issue, or the maintainer can invite them. The maintainer
decides, and a new maintainer is added to this file through a pull request.

## Changing this document

This document changes like any other file: through a pull request that the
maintainer reviews and merges the same way.
