from app.watcher.tailer import FileTailer


def test_returns_only_appended_lines(tmp_path):
    f, t = tmp_path / "a.log", FileTailer()
    f.write_bytes(b"one\ntwo\n")
    assert t.read_new(f) == b"one\ntwo\n"
    assert t.read_new(f) == b""
    with open(f, "ab") as h:
        h.write(b"three\n")
    assert t.read_new(f) == b"three\n"


def test_partial_line_held_until_newline(tmp_path):
    f, t = tmp_path / "a.log", FileTailer()
    f.write_bytes(b"one\ntw")
    assert t.read_new(f) == b"one\n"
    assert t.read_new(f) == b""
    with open(f, "ab") as h:
        h.write(b"o\n")
    assert t.read_new(f) == b"two\n"


def test_truncation_resets_offset(tmp_path):
    f, t = tmp_path / "a.log", FileTailer()
    f.write_bytes(b"aaaa\nbbbb\n")
    t.read_new(f)
    f.write_bytes(b"c\n")
    assert t.read_new(f) == b"c\n"


def test_missing_and_empty_file_return_empty(tmp_path):
    t = FileTailer()
    assert t.read_new(tmp_path / "none.log") == b""
    (tmp_path / "e.log").write_bytes(b"")
    assert t.read_new(tmp_path / "e.log") == b""


def test_cap_limits_bytes_and_continues_next_call(tmp_path):
    f, t = tmp_path / "a.log", FileTailer()
    f.write_bytes(b"aaaa\nbbbb\ncccc\n")
    assert t.read_new(f, max_bytes=10) == b"aaaa\nbbbb\n"
    assert t.read_new(f, max_bytes=10) == b"cccc\n"


def test_line_longer_than_cap_is_read_whole(tmp_path):
    f, t = tmp_path / "a.log", FileTailer()
    f.write_bytes(b"x" * 30 + b"\nnext\n")
    assert t.read_new(f, max_bytes=10) == b"x" * 30 + b"\n"
    assert t.read_new(f, max_bytes=10) == b"next\n"


def test_long_unterminated_line_is_not_consumed(tmp_path):
    f, t = tmp_path / "a.log", FileTailer()
    f.write_bytes(b"x" * 30)
    assert t.read_new(f, max_bytes=10) == b""
    assert t.offset == 0
