import json

from audit.audit_logger import sanitize_metadata
from tests.conftest import GOOD_PW, OTHER_PW


def test_sanitizer_redacts_sensitive_keys():
    out = sanitize_metadata({"password": "x", "reset_token": "y", "api_key": "z", "session_id": "s",
                             "password_hash": "h", "ok": "visible", "nested": {"Authorization": "b"}})
    assert out["password"] == out["reset_token"] == out["api_key"] == out["session_id"] == "[REDACTED]"
    assert out["password_hash"] == "[REDACTED]" and out["ok"] == "visible"
    assert out["nested"]["Authorization"] == "[REDACTED]"


def test_logger_writes_json_lines_and_db(ctx, alice):
    ctx.audit.log("TEST_EVENT", "INFO", alice.id, password="hunter2", note="hi")
    lines = [json.loads(l) for l in open(ctx.settings.audit_log_path)]
    last = lines[-1]
    assert last["event_type"] == "TEST_EVENT" and last["metadata"]["password"] == "[REDACTED]"
    assert ctx.security_events.recent(1)[0]["event_type"] == "TEST_EVENT"


def test_no_secret_ever_reaches_logs(ctx, alice, mailbox, clock):
    res = ctx.auth.login("alice", GOOD_PW)
    ctx.reset.request_reset("alice", ip_label="t")
    token = mailbox.messages[-1][1]
    ctx.reset.reset_password(token, OTHER_PW, ip_label="t")
    with ctx.db.connect() as c:
        db_text = " ".join(r[0] for r in c.execute("SELECT details_json FROM security_events"))
    file_text = open(ctx.settings.audit_log_path).read()
    for secret in (GOOD_PW, OTHER_PW, token, res.session_token):
        assert secret not in db_text and secret not in file_text


def test_expected_event_types_are_emitted(ctx, alice):
    ctx.auth.login("alice", GOOD_PW)
    types = ctx.security_events.count_by_type()
    assert {"USER_REGISTERED", "LOGIN_SUCCESS", "SESSION_CREATED"} <= types.keys()
