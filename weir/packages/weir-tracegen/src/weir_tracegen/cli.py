import click

from weir.schema.trace import encode_canonical_trace
from weir_tracegen.emitter import emit, emit_degraded


@click.group()
def main() -> None:
    pass


@main.command("emit")
@click.argument("scenario_name")
@click.option("--seed", type=int, required=True)
@click.option(
    "--degrade-index",
    type=int,
    default=None,
    help="Emit a partially-degraded variant: strip this tool_call node's args, mark it degraded.",
)
def emit_cmd(scenario_name: str, seed: int, degrade_index: int | None) -> None:
    if degrade_index is None:
        trace = emit(scenario_name, seed=seed)
    else:
        trace = emit_degraded(scenario_name, seed=seed, degrade_tool_call_index=degrade_index)
    click.echo(encode_canonical_trace(trace).decode())


if __name__ == "__main__":
    main()
