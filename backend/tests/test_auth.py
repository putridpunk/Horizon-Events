from datetime import timedelta

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.auth import passwords, service
from app.auth.guard import LoginThrottle, login_throttle, required_role, set_session_factory
from app.database.auth_models import AuditRow, AuthSessionRow, UserRow
from app.database.connection import get_session
from app.domain import utcnow
from app.main import app

GOOD = "correct horse battery"


# ---- passwords -------------------------------------------------------------------------------------------------
def test_passwords_are_salted_hashes_that_verify():
    a, b = passwords.hash_password(GOOD), passwords.hash_password(GOOD)
    assert a != b and GOOD not in a and a.startswith("pbkdf2_sha256$600000$")
    assert passwords.verify_password(GOOD, a) and not passwords.verify_password("wrong password!!", a)
    assert not passwords.verify_password(GOOD, "garbage") and not passwords.verify_password(GOOD, "x$y$z$w")


@pytest.mark.parametrize("password,user,message", [
    ("short", "bob", "at least 12"), ("x" * 201, "bob", "at most 200"), ("bobby-bobby", "bobby-bobby", "at least 12"),
    ("aaaaaaaaaaaaaaaa", "bob", "repetitive"), ("Alice.Smith.123", "alice.smith.123", "same as the user name")])
def test_weak_passwords_are_refused_with_a_reason(password, user, message):
    with pytest.raises(passwords.PasswordError, match=message):
        passwords.check_policy(password, user)


def test_an_over_long_password_is_cut_not_hashed_forever():
    stored = passwords.hash_password("p" * 200)
    assert passwords.verify_password("p" * 200 + "extra", stored)  # only the first 200 characters count


# ---- the service -----------------------------------------------------------------------------------------------
def test_usernames_are_cleaned_and_unique(session):
    user = service.create_user(session, "  Alice.Smith ", GOOD, "analyst")
    assert user.username == "alice.smith" and user.role == "analyst"
    for bad in ("", "ab", "-lead", "has space", "x" * 65, "semi;colon"):
        with pytest.raises(service.AuthError, match="user name"):
            service.create_user(session, bad, GOOD, "viewer")
    with pytest.raises(service.AuthError, match="already taken"):
        service.create_user(session, "ALICE.SMITH", GOOD, "viewer")
    with pytest.raises(service.AuthError, match="role must be"):
        service.create_user(session, "bob.b", GOOD, "root")


def test_five_wrong_passwords_lock_the_account_even_against_the_right_one(session):
    service.create_user(session, "alice", GOOD, "viewer")
    now = utcnow()
    for _ in range(4):
        assert service.authenticate(session, "alice", "nope nope nope", now) is None
    assert service.authenticate(session, "alice", GOOD, now) is not None  # a success resets the count
    for _ in range(5):
        assert service.authenticate(session, "alice", "nope nope nope", now) is None
    with pytest.raises(service.Locked):
        service.authenticate(session, "alice", GOOD, now + timedelta(minutes=14))
    assert service.authenticate(session, "alice", GOOD, now + timedelta(minutes=16)) is not None


def test_unknown_and_disabled_users_just_fail(session):
    assert service.authenticate(session, "ghost", "whatever password") is None
    u = service.create_user(session, "carol", GOOD, "viewer")
    u.disabled = True
    assert service.authenticate(session, "carol", GOOD) is None


def test_sessions_expire_when_idle_and_after_a_week_and_store_only_a_hash(session):
    user = service.create_user(session, "alice", GOOD, "viewer")
    now = utcnow()
    token = service.start_session(session, user, now)
    assert session.query(AuthSessionRow).one().token_hash != token
    assert service.resolve_session(session, token, now + timedelta(hours=11)).username == "alice"
    assert service.resolve_session(session, token, now + timedelta(hours=11) + timedelta(hours=13)) is None  # idle too long
    token2 = service.start_session(session, user, now)
    for hours in range(11, 24 * 7, 11):  # kept alive by activity...
        assert service.resolve_session(session, token2, now + timedelta(hours=hours)) is not None
    assert service.resolve_session(session, token2, now + timedelta(days=7, minutes=1)) is None  # ...but not beyond a week
    assert service.resolve_session(session, None) is None and service.resolve_session(session, "forged") is None


def test_the_last_administrator_cannot_be_removed(session):
    admin = service.create_user(session, "root.admin", GOOD, "admin")
    other = service.create_user(session, "second.admin", GOOD, "admin")
    assert service.can_remove_admin(session, admin) is True
    other.disabled = True
    assert service.can_remove_admin(session, admin) is False
    assert service.can_remove_admin(session, service.create_user(session, "viewer.v", GOOD, "viewer")) is True


def test_the_first_administrator_can_come_from_the_environment(session, monkeypatch):
    monkeypatch.setenv("HORIZON_ADMIN_USER", "Boss")
    monkeypatch.setenv("HORIZON_ADMIN_PASSWORD", GOOD)
    assert service.bootstrap_from_environment(session) is True and session.query(UserRow).one().role == "admin"
    assert service.bootstrap_from_environment(session) is False  # only when there are no users
    assert session.query(AuditRow).one().action == "setup"


def test_auth_applies_to_servers_only(monkeypatch):
    monkeypatch.delenv("HORIZON_AUTH", raising=False)
    assert service.enabled() is False
    monkeypatch.setenv("HORIZON_AUTH", "1")
    assert service.enabled() is True
    monkeypatch.setenv("HORIZON_DESKTOP", "1")
    assert service.enabled() is False


# ---- what each role may call -----------------------------------------------------------------------------------
@pytest.mark.parametrize("method,path,role", [
    ("GET", "/api/health", None), ("GET", "/api/auth/status", None), ("POST", "/api/auth/login", None),
    ("POST", "/api/auth/setup", None), ("POST", "/api/auth/logout", "viewer"), ("POST", "/api/auth/password", "viewer"),
    ("GET", "/api/alerts", "viewer"), ("GET", "/api/events/export", "viewer"), ("GET", "/api/stream", "viewer"),
    ("GET", "/docs", "viewer"), ("GET", "/openapi.json", "viewer"), ("GET", "/api/rules", "viewer"),
    ("PATCH", "/api/alerts/3", "analyst"), ("PATCH", "/api/alerts/3/triage", "analyst"), ("POST", "/api/alerts/3/suppress", "analyst"),
    ("POST", "/api/incidents/1/notes", "analyst"), ("POST", "/api/searches", "analyst"), ("DELETE", "/api/suppressions/2", "analyst"),
    ("POST", "/api/imports", "analyst"), ("POST", "/api/rules/replay", "analyst"),
    ("PATCH", "/api/rules/HZ-001", "admin"), ("POST", "/api/rules/custom", "admin"), ("POST", "/api/rules/sigma", "admin"),
    ("GET", "/api/users", "admin"), ("POST", "/api/users", "admin"), ("GET", "/api/audit", "admin"),
    ("GET", "/api/notifications", "admin"), ("POST", "/api/notifications/1/test", "admin"),
    ("GET", "/api/data/status", "admin"), ("PUT", "/api/desktop/settings", "admin"), ("PUT", "/api/geoip", "admin"),
    ("POST", "/api/mitigation/4/approve", "admin"), ("POST", "/api/scans", "admin"), ("PATCH", "/api/collectors/x", "admin"),
    ("POST", "/api/intel/import", "admin"), ("POST", "/api/report-schedules", "admin"), ("POST", "/api/ml/train", "admin"),
    ("GET", "/api/update", "admin"), ("DELETE", "/api/whatever/new", "admin"), ("POST", "/api/whatever/new", "admin"),
])
def test_required_roles(method, path, role):
    assert required_role(method, path) == role


def test_a_trailing_slash_does_not_dodge_a_rule():
    assert required_role("GET", "/api/users/") == "admin" and required_role("GET", "/api/auth/status/") is None


def test_the_throttle_limits_attempts_and_forgets_them():
    now = [0.0]
    t = LoginThrottle(limit=3, window=60, clock=lambda: now[0])
    assert [t.allow("a") for _ in range(4)] == [True, True, True, False]
    assert t.allow("b") is True  # other addresses are unaffected
    now[0] = 61
    assert t.allow("a") is True


# ---- through the whole app -------------------------------------------------------------------------------------
@pytest.fixture
def server(engine, monkeypatch):
    monkeypatch.setenv("HORIZON_AUTH", "1")
    monkeypatch.delenv("HORIZON_DESKTOP", raising=False)
    set_session_factory(lambda: Session(engine, expire_on_commit=False))

    def override():
        with Session(engine, expire_on_commit=False) as s:
            yield s
    app.dependency_overrides[get_session] = override
    login_throttle.reset()
    app.state.setup_token = "setup-code-123"
    yield TestClient(app)
    app.dependency_overrides.clear()
    set_session_factory(None)
    login_throttle.reset()


def client_for(engine, role, name=None):
    """A signed-in client of another browser."""
    c = TestClient(app)
    name = name or f"{role}.user"
    with Session(engine, expire_on_commit=False) as s:
        if s.query(UserRow).filter_by(username=name).first() is None:
            service.create_user(s, name, GOOD, role)
            s.commit()
    assert c.post("/api/auth/login", json={"username": name, "password": GOOD}).status_code == 200
    return c


def test_nothing_is_open_before_sign_in_except_the_page_status_and_health(server):
    assert server.get("/api/health").status_code == 200
    s = server.get("/api/auth/status").json()
    assert s == {"enabled": True, "setup_required": True, "user": None}
    for method, path in [("get", "/api/alerts"), ("get", "/api/events"), ("get", "/api/stream"), ("get", "/docs"),
                         ("get", "/openapi.json"), ("post", "/api/imports"), ("patch", "/api/rules/HZ-001"),
                         ("get", "/api/users")]:
        r = getattr(server, method)(path)
        assert r.status_code == 401 and r.json()["detail"] == "Sign in to continue.", path
    assert server.get("/").status_code != 401  # the web page itself holds no data


def test_setup_needs_the_code_and_works_once(server):
    body = {"username": "Admin.One", "password": GOOD}
    assert server.post("/api/auth/setup", json={**body, "token": "wrong"}).status_code == 403
    assert server.post("/api/auth/setup", json={**body, "token": "setup-code-123", "password": "short"}).status_code == 422
    r = server.post("/api/auth/setup", json={**body, "token": "setup-code-123"})
    assert r.status_code == 201 and r.json() == {"user": {"username": "admin.one", "role": "admin"}}
    assert "horizon_session" in r.cookies and app.state.setup_token is None
    assert server.get("/api/alerts").status_code == 200  # signed in by the setup
    assert TestClient(app).post("/api/auth/setup", json={**body, "token": "setup-code-123", "username": "other.one"}).status_code == 409


def test_setup_is_refused_without_a_code_on_record(server):
    app.state.setup_token = None
    r = server.post("/api/auth/setup", json={"token": "", "username": "someone", "password": GOOD})
    assert r.status_code == 409


def test_login_cookie_is_hardened_and_logout_ends_the_session(server, engine):
    client_for(engine, "admin", "root.admin")
    r = server.post("/api/auth/login", json={"username": "ROOT.ADMIN", "password": GOOD})
    header = r.headers["set-cookie"].lower()
    assert "httponly" in header and "samesite=strict" in header and "path=/" in header
    assert server.get("/api/auth/status").json()["user"] == {"username": "root.admin", "role": "admin"}
    assert server.post("/api/auth/logout").status_code == 200
    assert server.get("/api/alerts").status_code == 401 and server.get("/api/auth/status").json()["user"] is None


def test_a_wrong_password_or_name_gives_the_same_answer_and_is_recorded(server, engine):
    client_for(engine, "viewer", "vera.v")
    a = server.post("/api/auth/login", json={"username": "vera.v", "password": "wrong password"})
    b = server.post("/api/auth/login", json={"username": "nobody.here", "password": "wrong password"})
    assert (a.status_code, a.json()) == (b.status_code, b.json()) == (401, {"detail": "Wrong user name or password."})
    with Session(engine) as s:
        assert [r.action for r in s.query(AuditRow).filter(AuditRow.action == "login_failed")] == ["login_failed", "login_failed"]


def test_an_account_locks_after_five_failures_through_the_api(server, engine):
    client_for(engine, "viewer", "lock.me")
    for _ in range(5):
        server.post("/api/auth/login", json={"username": "lock.me", "password": "wrong password"})
    r = server.post("/api/auth/login", json={"username": "lock.me", "password": GOOD})
    assert r.status_code == 429 and "locked" in r.json()["detail"]


def test_too_many_attempts_from_one_address_are_slowed(server):
    codes = [server.post("/api/auth/login", json={"username": f"user{i}.x", "password": "wrong password"}).status_code
             for i in range(22)]
    assert codes[:20] == [401] * 20 and codes[20:] == [429, 429]


def test_roles_are_enforced_on_real_requests(server, engine):
    viewer, analyst, admin = (client_for(engine, r) for r in ("viewer", "analyst", "admin"))
    assert viewer.get("/api/alerts").status_code == 200 and viewer.get("/api/events/export").status_code == 200
    r = viewer.post("/api/searches", json={"name": "x", "query": "user:a"})
    assert r.status_code == 403 and "viewer" in r.json()["detail"] and "analyst" in r.json()["detail"]
    assert viewer.get("/api/users").status_code == 403 and viewer.get("/api/notifications").status_code == 403
    assert analyst.post("/api/searches", json={"name": "x", "query": "user:a"}).status_code == 201
    assert analyst.patch("/api/rules/HZ-001", json={"enabled": False}).status_code == 403
    assert analyst.get("/api/users").status_code == 403
    assert admin.patch("/api/rules/HZ-001", json={"enabled": False}).status_code == 200
    assert admin.get("/api/users").status_code == 200 and admin.get("/api/audit").status_code == 200


def test_a_disabled_user_loses_access_at_once(server, engine):
    admin, viewer = client_for(engine, "admin"), client_for(engine, "viewer")
    assert viewer.get("/api/alerts").status_code == 200
    uid = next(u["id"] for u in admin.get("/api/users").json()["items"] if u["username"] == "viewer.user")
    assert admin.patch(f"/api/users/{uid}", json={"disabled": True}).status_code == 200
    assert viewer.get("/api/alerts").status_code == 401
    assert TestClient(app).post("/api/auth/login", json={"username": "viewer.user", "password": GOOD}).status_code == 401


def test_user_administration_protects_the_last_admin_and_yourself(server, engine):
    admin = client_for(engine, "admin", "only.admin")
    me = next(u for u in admin.get("/api/users").json()["items"] if u["username"] == "only.admin")
    assert admin.patch(f"/api/users/{me['id']}", json={"role": "viewer"}).status_code == 409
    assert admin.patch(f"/api/users/{me['id']}", json={"disabled": True}).status_code == 409
    assert admin.delete(f"/api/users/{me['id']}").status_code == 409
    new = admin.post("/api/users", json={"username": "New.Person", "password": GOOD, "role": "analyst"})
    assert new.status_code == 201 and new.json()["username"] == "new.person" and "password" not in str(new.json())
    assert admin.post("/api/users", json={"username": "new.person", "password": GOOD}).status_code == 422
    assert admin.post("/api/users", json={"username": "weak.one", "password": "short"}).status_code == 422
    assert admin.patch(f"/api/users/{new.json()['id']}", json={"role": "wizard"}).status_code == 422
    assert admin.patch(f"/api/users/{new.json()['id']}", json={"role": "admin"}).json()["role"] == "admin"
    assert admin.delete("/api/users/999").status_code == 404
    assert admin.patch(f"/api/users/{me['id']}", json={"role": "viewer"}).status_code == 200  # a second admin exists now


def test_resetting_a_password_signs_that_user_out_and_unlocks(server, engine):
    admin, viewer = client_for(engine, "admin"), client_for(engine, "viewer", "reset.me")
    uid = next(u["id"] for u in admin.get("/api/users").json()["items"] if u["username"] == "reset.me")
    for _ in range(5):
        TestClient(app).post("/api/auth/login", json={"username": "reset.me", "password": "wrong password"})
    assert admin.get("/api/users").json()["items"][0] is not None
    new = "a brand new passphrase"
    assert admin.patch(f"/api/users/{uid}", json={"password": new}).status_code == 200
    assert viewer.get("/api/alerts").status_code == 401  # old session ended
    assert TestClient(app).post("/api/auth/login", json={"username": "reset.me", "password": new}).status_code == 200


def test_changing_your_own_password_keeps_this_browser_and_ends_the_others(server, engine):
    first = client_for(engine, "viewer", "change.me")
    other = TestClient(app)
    other.post("/api/auth/login", json={"username": "change.me", "password": GOOD})
    assert first.post("/api/auth/password", json={"current_password": "not it at all", "new_password": "another good one!"}).status_code == 403
    assert first.post("/api/auth/password", json={"current_password": GOOD, "new_password": "short"}).status_code == 422
    assert first.post("/api/auth/password", json={"current_password": GOOD, "new_password": "another good one!"}).status_code == 200
    assert first.get("/api/alerts").status_code == 200 and other.get("/api/alerts").status_code == 401
    assert TestClient(app).post("/api/auth/login", json={"username": "change.me", "password": "another good one!"}).status_code == 200


def test_the_audit_trail_records_who_did_what(server, engine):
    admin = client_for(engine, "admin")
    admin.post("/api/users", json={"username": "audited.u", "password": GOOD, "role": "viewer"})
    actions = [(a["actor"], a["action"], a["detail"]) for a in admin.get("/api/audit").json()["items"]]
    assert ("admin.user", "user_created", "audited.u as viewer") in actions and any(a[1] == "login" for a in actions)
    assert GOOD not in str(actions)


def test_when_sign_in_is_off_nothing_changes(engine, monkeypatch):
    monkeypatch.delenv("HORIZON_AUTH", raising=False)

    def override():
        with Session(engine, expire_on_commit=False) as s:
            yield s
    app.dependency_overrides[get_session] = override
    try:
        c = TestClient(app)
        assert c.get("/api/auth/status").json() == {"enabled": False, "setup_required": False, "user": None}
        assert c.get("/api/alerts").status_code == 200 and c.patch("/api/rules/HZ-001", json={"enabled": True}).status_code == 200
        assert c.post("/api/auth/login", json={"username": "a.b.c", "password": GOOD}).status_code == 404
    finally:
        app.dependency_overrides.clear()
