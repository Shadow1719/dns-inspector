"""Regression test for a real-DEV `SyntaxWarning` from the JS regex embedded
in `mapCompactNumber()`.

`app.py`'s `HTML` template is a plain (non-raw) triple-quoted Python string, so
any `\\.` sequence inside its embedded JavaScript that is not a recognised
Python escape (`\\\\`, `\\n`, ...) is compiled as an "invalid escape sequence"
`SyntaxWarning` even though the resulting JS text is correct. Compiling the
whole file with warnings escalated to errors catches any such site without
depending on a specific line number.
"""

import warnings
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent


def test_app_source_compiles_without_syntax_warnings():
    source = (REPO_ROOT / "app.py").read_text(encoding="utf-8")
    with warnings.catch_warnings():
        warnings.simplefilter("error", SyntaxWarning)
        compile(source, "app.py", "exec")
