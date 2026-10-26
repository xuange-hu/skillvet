"""Windows console encoding regression.

Observed in CI on ``windows-latest``::

    File "...\\skillvet\\cli.py", line 175, in _cmd_demo
        print(
    File "...\\encodings\\cp1252.py", line 19, in encode
    UnicodeEncodeError: 'charmap' codec can't encode character '\\u200b'

`skillvet demo` writes a hostile fixture that contains a zero-width space, then
prints it back as evidence — which crashes on the default Windows console
encoding. The demo is the first command a visitor runs, so on Windows the tool
looked broken on contact. These tests pin the fix.
"""

from __future__ import annotations

import io

from skillvet.cli import force_utf8_stdio


class _RecordingStream:
    """Stands in for a Windows console: an encoding that cannot do U+200B."""

    def __init__(self, encoding: str) -> None:
        self.encoding = encoding
        self.buffer: list[str] = []
        self.reconfigured: list[dict] = []

    def write(self, text: str) -> int:
        self.buffer.append(text)
        return len(text)

    def reconfigure(self, **kwargs) -> None:
        self.reconfigured.append(kwargs)
        self.encoding = kwargs.get("encoding", self.encoding)

    def flush(self) -> None:
        return None

    def getvalue(self) -> str:
        return "".join(self.buffer)


def test_windows_console_is_reconfigured_to_utf8(monkeypatch):
    out, err = _RecordingStream("cp1252"), _RecordingStream("cp1252")
    monkeypatch.setattr("sys.stdout", out)
    monkeypatch.setattr("sys.stderr", err)

    force_utf8_stdio()

    assert out.reconfigured == [{"encoding": "utf-8", "errors": "replace"}]
    assert err.encoding == "utf-8"


def test_already_utf8_streams_are_left_alone(monkeypatch):
    out = _RecordingStream("utf-8")
    monkeypatch.setattr("sys.stdout", out)
    monkeypatch.setattr("sys.stderr", out)

    force_utf8_stdio()

    assert out.reconfigured == []


def test_streams_without_reconfigure_do_not_explode(monkeypatch):
    plain = io.StringIO()  # no .reconfigure at all
    monkeypatch.setattr("sys.stdout", plain)
    monkeypatch.setattr("sys.stderr", plain)

    force_utf8_stdio()  # must not raise


def test_the_detected_characters_are_printable_after_the_fix(monkeypatch):
    """The actual payload that used to kill the Windows demo command."""
    out = _RecordingStream("cp1252")
    monkeypatch.setattr("sys.stdout", out)
    monkeypatch.setattr("sys.stderr", out)
    force_utf8_stdio()

    print("invisible: \u200b\u202e\u2066")  # ZWSP, RLO, LRI

    assert "\u200b" in out.getvalue()
