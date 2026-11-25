import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.database.models import AlertRow
from app.domain import utcnow
from app.main import app
from app.shell import autostart
from app.shell.notifier import AlertNotifier
from app.shell.settings import ShellError, ShellSettings, load

EXE = r"C:\Program Files\Horizon Events\HorizonEvents.exe"


class FakeRegistry:
    """A stand-in for winreg that keeps one key in memory."""
    HKEY_CURRENT_USER, KEY_READ, KEY_SET_VALUE, REG_SZ = "HKCU", 1, 2, 1

    def __init__(self):
        self.values = {}
        self.exists = False

    class _Key:
        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    def OpenKey(self, root, path, reserved, access):
        if not self.exists:
            raise FileNotFoundError(path)
        return self._Key()

    def CreateKey(self, root, path):
        self.exists = True
        return self._Key()

    def QueryValueEx(self, key, name):
        if name not in self.values:
            raise FileNotFoundError(name)
        return self.values[name], self.REG_SZ

    def SetValueEx(self, key, name, reserved, kind, value):
        self.values[name] = value

    def DeleteValue(self, key, name):
        if name not in self.values:
            raise FileNotFoundError(name)
        del self.values[name]


# ---- start with Windows ----------------------------------------------------------------------------------------
def test_autostart_writes_a_quoted_command_that_starts_in_the_tray():
    reg = FakeRegistry()
    autostart.set_enabled(True, EXE, reg, frozen=True)
    assert reg.values["HorizonEvents"] == f'"{EXE}" --background'
    assert autostart.is_enabled(EXE, reg) is True


def test_autostart_can_be_switched_off_and_off_twice():
    reg = FakeRegistry()
    autostart.set_enabled(True, EXE, reg, frozen=True)
    autostart.set_enabled(False, EXE, reg)
    autostart.set_enabled(False, EXE, reg)
    assert autostart.is_enabled(EXE, reg) is False


def test_autostart_is_not_enabled_for_a_different_program():
    reg = FakeRegistry()
    autostart.set_enabled(True, r"C:\Old\HorizonEvents.exe", reg, frozen=True)
    assert autostart.is_enabled(EXE, reg) is False


@pytest.mark.parametrize("exe,frozen", [(EXE, False), (None, True), ("relative.exe", True)])
def test_autostart_refuses_when_not_running_as_the_installed_app(exe, frozen):
    reg = FakeRegistry()
    with pytest.raises(autostart.AutostartError, match="installed app"):
        autostart.set_enabled(True, exe, reg, frozen=frozen)
    assert reg.values == {}


# ---- settings --------------------------------------------------------------------------------------------------
@pytest.fixture
def factory(engine):
    return lambda: Session(engine, expire_on_commit=False)


def test_defaults_keep_the_old_behaviour_and_notify_about_critical_alerts(session):
    assert load(session) == {"run_in_background": False, "notify": "critical"}


def test_settings_roundtrip(factory):
    shell = ShellSettings(factory, EXE, FakeRegistry(), frozen=True)
    got = shell.update(run_in_background=True, notify="high", start_with_windows=True)
    assert got == {"run_in_background": True, "notify": "high", "start_with_windows": True}
    assert shell.keeps_running_in_background() is True
    assert shell.get()["start_with_windows"] is True
    assert shell.update(start_with_windows=False)["start_with_windows"] is False


def test_bad_settings_are_refused_and_change_nothing(factory):
    shell = ShellSettings(factory, EXE, FakeRegistry(), frozen=False)
    with pytest.raises(ShellError, match="critical, high or off"):
        shell.update(notify="loud")
    with pytest.raises(ShellError, match="installed app"):
        shell.update(run_in_background=True, start_with_windows=True)
    assert shell.get()["run_in_background"] is False


# ---- notifications ---------------------------------------------------------------------------------------------
def add_alert(factory, severity="critical", rule="Repeated login failures", ip="8.8.4.4", status="OPEN"):
    with factory() as s:
        a = AlertRow(rule_id="HZ-001", rule_name=rule, severity=severity, status=status, key=f"{rule}{ip}{severity}{utcnow()}",
                     description="d", source_ip=ip, username="admin", created_at=utcnow(), last_seen=utcnow())
        s.add(a)
        s.commit()


@pytest.fixture
def sent():
    return []


def notifier(factory, sent):
    return AlertNotifier(factory, lambda title, message: sent.append((title, message)))


def test_old_alerts_are_not_announced_when_the_app_starts(factory, sent):
    add_alert(factory)
    n = notifier(factory, sent)
    assert n.tick() == 0 and sent == []


def test_a_new_critical_alert_is_announced_once(factory, sent):
    n = notifier(factory, sent)
    add_alert(factory)
    assert n.tick() == 1
    assert sent == [("Horizon Events: Critical alert", "Repeated login failures (8.8.4.4 admin)")]
    assert n.tick() == 0 and len(sent) == 1


def test_high_alerts_need_the_high_setting(factory, sent):
    n = notifier(factory, sent)
    add_alert(factory, severity="high")
    assert n.tick() == 0
    ShellSettings(factory).update(notify="high")
    add_alert(factory, severity="high", rule="Account lockouts")
    assert n.tick() == 1 and "High alert" in sent[0][0]


def test_notifications_can_be_switched_off(factory, sent):
    ShellSettings(factory).update(notify="off")
    n = notifier(factory, sent)
    add_alert(factory)
    assert n.tick() == 0 and sent == []


def test_many_alerts_are_summarised_in_one_notification(factory, sent):
    n = notifier(factory, sent)
    for i in range(6):
        add_alert(factory, rule=f"Rule {i}")
    assert n.tick() == 6
    assert len(sent) == 1 and sent[0][0] == "Horizon Events: 6 new alerts"
    assert sent[0][1].splitlines()[-1] == "and 3 more" and len(sent[0][1].splitlines()) == 4


def test_resolved_alerts_are_not_announced(factory, sent):
    n = notifier(factory, sent)
    add_alert(factory, status="RESOLVED")
    assert n.tick() == 0


# ---- API -------------------------------------------------------------------------------------------------------
@pytest.fixture
def client(factory):
    app.state.shell = ShellSettings(factory, EXE, FakeRegistry(), frozen=True)
    yield TestClient(app)
    app.state.shell = None


def test_api_reports_when_it_is_not_the_desktop_app():
    app.state.shell = None
    c = TestClient(app)
    assert c.get("/api/desktop/settings").json() == {"enabled": False}
    assert c.put("/api/desktop/settings", json={"notify": "off"}).status_code == 409


def test_api_get_and_update(client):
    assert client.get("/api/desktop/settings").json() == {"enabled": True, "run_in_background": False, "notify": "critical",
                                                         "start_with_windows": False}
    got = client.put("/api/desktop/settings", json={"run_in_background": True, "start_with_windows": True}).json()
    assert got["run_in_background"] is True and got["start_with_windows"] is True


def test_api_rejects_bad_values(client):
    res = client.put("/api/desktop/settings", json={"notify": "loud"})
    assert res.status_code == 422 and isinstance(res.json()["detail"], str)
