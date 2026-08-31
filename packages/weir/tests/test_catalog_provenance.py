from weir.catalog import DEFAULT_CATALOG
from weir.catalog._types import Catalog


def test_default_catalog_has_empty_untrusted_sources() -> None:
    assert DEFAULT_CATALOG.untrusted_sources == []


def test_catalog_untrusted_sources_roundtrips() -> None:
    import msgspec

    c = Catalog(sources=[], sinks=[], remediations={}, untrusted_sources=["read_file"])
    assert msgspec.json.decode(msgspec.json.encode(c), type=Catalog).untrusted_sources == [
        "read_file"
    ]
