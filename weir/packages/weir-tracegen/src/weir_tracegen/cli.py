import json

import click

from weir_tracegen._clock import SeededClock
from weir_tracegen._rng import SeededRng


@click.group()
def main() -> None:
    pass


@main.command("emit-smoke")
@click.option("--seed", type=int, required=True)
def emit_smoke(seed: int) -> None:
    """L6 smoke command proving the seeded core is deterministic end-to-end.
    Superseded by real scenario emission once L7/L8 land."""
    rng = SeededRng(seed)
    clock = SeededClock()
    payload = {
        "seed": seed,
        "ticks": [clock.tick() for _ in range(3)],
        "rolls": [rng.randint(0, 1_000_000) for _ in range(5)],
    }
    click.echo(json.dumps(payload, sort_keys=True))


if __name__ == "__main__":
    main()
