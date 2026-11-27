import socket

from app.desktop import pick_free_port, remembered_port


def test_the_first_launch_picks_a_free_port_and_remembers_it(tmp_path):
    f = tmp_path / "port"
    port = remembered_port(f)
    assert 1024 <= port <= 65535 and f.read_text() == str(port)


def test_later_launches_use_the_same_port_so_the_window_keeps_its_settings(tmp_path):
    f = tmp_path / "port"
    first = remembered_port(f)
    assert remembered_port(f) == first == remembered_port(f)


def test_a_busy_port_gets_a_new_one_that_is_then_remembered(tmp_path):
    f = tmp_path / "port"
    first = remembered_port(f)
    with socket.socket() as busy:
        busy.bind(("127.0.0.1", first))
        second = remembered_port(f)
        assert second != first and f.read_text() == str(second)
    assert remembered_port(f) == second


def test_a_damaged_or_silly_file_is_replaced(tmp_path):
    f = tmp_path / "port"
    for junk in ("", "abc", "80", "99999", "-5"):
        f.write_text(junk)
        port = remembered_port(f)
        assert 1024 <= port <= 65535 and f.read_text() == str(port)


def test_an_unwritable_location_still_gives_a_working_port(tmp_path):
    port = remembered_port(tmp_path / "missing-folder" / "port")
    assert 1024 <= port <= 65535 and pick_free_port() > 0
