"""The canary runner: plants fake canaries, runs a program's flows against a
loopback mock, and judges the captured telemetry with `weir canary judge`.

Its contract is weir's docs/canary.md. The runner is a test-time tool for a
developer's machine or a CI runner, never imported by production code.
"""
