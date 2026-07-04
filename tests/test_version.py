import asfops


def test_version() -> None:
    assert isinstance(asfops.__version__, str)
    assert asfops.__version__.count(".") == 2
