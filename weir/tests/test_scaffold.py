import weir
import weir_tracegen


def test_packages_import() -> None:
    assert weir is not None
    assert weir_tracegen is not None
