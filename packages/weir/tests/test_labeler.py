from pathlib import Path

from _harness.g1 import assert_byte_identical_across_hash_seeds

from weir.catalog import DEFAULT_CATALOG
from weir.graph import build_session_graph
from weir.label import label_graph
from weir.label.labeler import _find_destination
from weir.schema.trace import decode_canonical_trace

_FIXTURES_DIR = Path(__file__).parents[3] / "fixtures"
_PLANTED_IBAN = "DE89370400440532013000"


def _label(filename: str):  # noqa: ANN201
    trace = decode_canonical_trace((_FIXTURES_DIR / filename).read_bytes())
    return label_graph(build_session_graph(trace), DEFAULT_CATALOG)


def test_red_ticket_result_yields_iban_and_ticket_id_source_labels() -> None:
    labeled = _label("injection-exfil.json")
    matches = {
        label.matched_value for label in labeled.source_labels if label.node_index == 2
    }
    assert _PLANTED_IBAN in matches
    assert "18134063" in matches


def test_benign_ticket_result_yields_only_ticket_id_source_label() -> None:
    labeled = _label("injection-exfil-benign.json")
    matches = {
        label.matched_value for label in labeled.source_labels if label.node_index == 2
    }
    assert _PLANTED_IBAN not in matches
    assert "18134063" in matches


def test_sink_label_extracts_true_destination_not_tool_name() -> None:
    labeled = _label("injection-exfil.json")
    (send_email_label,) = [label for label in labeled.sink_labels if label.node_index == 6]
    assert send_email_label.tool_name == "send_email"
    assert send_email_label.true_destination == "user@acme.example"
    assert send_email_label.true_destination != send_email_label.tool_name


def test_no_sink_label_for_non_sink_tool_call() -> None:
    labeled = _label("injection-exfil.json")
    fetch_tickets_labels = [label for label in labeled.sink_labels if label.node_index == 1]
    assert fetch_tickets_labels == []


def test_recursive_extraction_finds_destination_nested_inside_lists_and_dicts() -> None:
    nested_args = {
        "envelope": {
            "recipients": [
                {"role": "cc", "address": "cc@example.com"},
                {"role": "to", "email": "nested-user@example.com"},
            ]
        },
        "subject": "hi",
    }
    assert _find_destination(nested_args, ["email"]) == "nested-user@example.com"


def test_recursive_extraction_prefers_top_level_key_over_nested() -> None:
    args = {"to": "top-level@example.com", "meta": {"to": "nested@example.com"}}
    assert _find_destination(args, ["to"]) == "top-level@example.com"


def test_recursive_extraction_returns_none_when_key_absent() -> None:
    assert _find_destination({"subject": "hi"}, ["to"]) is None


def test_label_graph_is_hash_seed_independent() -> None:
    fixture_path = _FIXTURES_DIR / "injection-exfil.json"
    code = (
        "from pathlib import Path\n"
        "from weir.catalog import DEFAULT_CATALOG\n"
        "from weir.graph import build_session_graph\n"
        "from weir.label import label_graph\n"
        "from weir.schema.trace import decode_canonical_trace\n"
        f"trace = decode_canonical_trace(Path(r'{fixture_path}').read_bytes())\n"
        "labeled = label_graph(build_session_graph(trace), DEFAULT_CATALOG)\n"
        "print([(m.node_index, m.matched_value) for m in labeled.source_labels])\n"
        "print([(s.node_index, s.true_destination) for s in labeled.sink_labels])\n"
    )
    assert_byte_identical_across_hash_seeds(code)
