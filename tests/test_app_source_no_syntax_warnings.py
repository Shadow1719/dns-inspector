"""Regression guard for a real production SyntaxWarning (Issue #61).

The DEV debug log the issue was filed against showed a Python SyntaxWarning
raised from `app.py`'s own source at import/compile time. The root cause was
`mapCompactNumber()`'s two regex literals -- embedded as JS source text
inside the plain (non-raw, non-f-string) `HTML = """..."""` Python string --
using inconsistent backslash escaping (`\\.0$` on one line, the invalid
`\.0$` on the other). `\.` is not a recognized Python string escape
sequence, so Python treats it as a literal two-character `\.` but also warns
about it. Both lines must produce the identical JS output; only the escaping
needed fixing.
"""

import warnings
from pathlib import Path

APP_PY = Path(__file__).resolve().parent.parent / "app.py"


def test_app_source_has_no_invalid_escape_sequence_syntaxwarning():
    source = APP_PY.read_text()
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        # compile() only parses/compiles to bytecode -- it does not execute
        # app.py, so this is safe to run without a live AdGuard/database.
        compile(source, str(APP_PY), "exec")
    escape_warnings = [
        w for w in caught
        if issubclass(w.category, SyntaxWarning) and "escape" in str(w.message)
    ]
    assert not escape_warnings, [str(w.message) for w in escape_warnings]


def test_map_compact_number_regex_escaping_is_consistent_between_both_branches():
    """Both branches of mapCompactNumber() must emit the identical JS regex
    (a literal dot before the trailing `0$`), not just avoid the warning."""
    body = APP_PY.read_text()
    assert r"replace(/\\.0$/, '') + 'M';" in body
    assert r"replace(/\\.0$/, '') + 'k';" in body
