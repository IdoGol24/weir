import pytest
from _harness.g1 import assert_byte_identical_across_hash_seeds
from click.testing import CliRunner

from weir.schema.trace import ToolCallPayload, decode_canonical_trace, encode_canonical_trace
from weir_tracegen.cli import main
from weir_tracegen.emitter import emit, emit_degraded
from weir_tracegen.scenarios import SCENARIOS


@pytest.mark.parametrize("name", list(SCENARIOS))
def test_emit_validates_against_canonical_trace_schema(name: str) -> None:
    trace = emit(name, seed=1)
    data = encode_canonical_trace(trace)
    assert decode_canonical_trace(data) == trace


@pytest.mark.parametrize("name", list(SCENARIOS))
def test_emit_same_seed_byte_identical(name: str) -> None:
    a = encode_canonical_trace(emit(name, seed=42))
    b = encode_canonical_trace(emit(name, seed=42))
    assert a == b


@pytest.mark.parametrize("name", list(SCENARIOS))
def test_emit_different_seed_differs(name: str) -> None:
    a = encode_canonical_trace(emit(name, seed=42))
    b = encode_canonical_trace(emit(name, seed=43))
    assert a != b


def test_emit_is_hash_seed_independent() -> None:
    code = (
        "from weir_tracegen.emitter import emit\n"
        "from weir.schema.trace import encode_canonical_trace\n"
        "import sys\n"
        "trace = emit('injection-exfil', seed=1)\n"
        "sys.stdout.buffer.write(encode_canonical_trace(trace))\n"
    )
    assert_byte_identical_across_hash_seeds(code)


def test_emit_degraded_marks_node_and_empties_args() -> None:
    trace = emit_degraded("injection-exfil-benign", seed=1, degrade_tool_call_index=1)
    node = trace.nodes[1]
    assert node.degraded is True
    assert isinstance(node.payload, ToolCallPayload)
    assert node.payload.args == {}
    # everything else is untouched
    baseline = emit("injection-exfil-benign", seed=1)
    assert trace.nodes[0] == baseline.nodes[0]
    assert trace.nodes[2:] == baseline.nodes[2:]
    assert trace.joins == baseline.joins


def test_emit_degraded_still_validates_against_schema() -> None:
    trace = emit_degraded("injection-exfil-benign", seed=1, degrade_tool_call_index=1)
    data = encode_canonical_trace(trace)
    assert decode_canonical_trace(data) == trace


def test_emit_degraded_rejects_non_tool_call_index() -> None:
    with pytest.raises(ValueError, match="not a tool_call"):
        emit_degraded("injection-exfil-benign", seed=1, degrade_tool_call_index=0)


def test_cli_emit_same_seed_byte_identical() -> None:
    runner = CliRunner()
    first = runner.invoke(main, ["emit", "injection-exfil", "--seed", "1"])
    second = runner.invoke(main, ["emit", "injection-exfil", "--seed", "1"])
    assert first.exit_code == 0
    assert first.output == second.output


def test_cli_emit_different_seed_differs() -> None:
    runner = CliRunner()
    a = runner.invoke(main, ["emit", "injection-exfil", "--seed", "1"])
    b = runner.invoke(main, ["emit", "injection-exfil", "--seed", "2"])
    assert a.output != b.output


def test_cli_emit_degraded_variant() -> None:
    runner = CliRunner()
    result = runner.invoke(
        main, ["emit", "injection-exfil-benign", "--seed", "1", "--degrade-index", "1"]
    )
    assert result.exit_code == 0
    trace = decode_canonical_trace(result.output)
    assert trace.nodes[1].degraded is True
