"""`python -m weir`: the `weir` command line. The status line setup runs
weir this way, so the settings do not depend on PATH."""

from weir.cli.main import main

main(prog_name="weir")
