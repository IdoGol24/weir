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
    "degrade_indices",
    type=int,
    multiple=True,
    help="Strip this tool_call node's args and mark it degraded. Repeatable.",
)
def emit_cmd(scenario_name: str, seed: int, degrade_indices: tuple[int, ...]) -> None:
    if not degrade_indices:
        trace = emit(scenario_name, seed=seed)
    else:
        trace = emit_degraded(
            scenario_name, seed=seed, degrade_tool_call_indices=list(degrade_indices)
        )
    click.echo(encode_canonical_trace(trace).decode())


if __name__ == "__main__":
    main()
