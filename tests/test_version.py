import re

import asfops


def test_version() -> None:
    # Version is derived from git tags by hatch-vcs: a clean release is
    # "X.Y.Z"; an unreleased working tree is "X.Y.Z.devN" (or "0.0.0" when the
    # package is neither built nor installed). Accept any PEP 440-ish string.
    assert isinstance(asfops.__version__, str)
    assert re.match(r"^\d+\.\d+\.\d+", asfops.__version__)
