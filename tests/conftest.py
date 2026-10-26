import pytest

from app_context import build_context
from auth.password_reset import ListMailbox
from config.settings import Settings
from utils import ManualClock

GOOD_PW = "Correct-Horse-Battery-9!"
OTHER_PW = "Purple-Tractor-Lantern-42?"


@pytest.fixture
def clock():
    return ManualClock()


@pytest.fixture
def mailbox():
    return ListMailbox()


@pytest.fixture
def settings(tmp_path):
    return Settings(app_env="test", database_url=f"sqlite:///{tmp_path / 't.db'}",
                    password_hash_iterations=1000, audit_log_path=str(tmp_path / "audit.log"),
                    mailbox_path=str(tmp_path / "mail.txt"), report_dir=str(tmp_path / "reports"))


@pytest.fixture
def ctx(settings, clock, mailbox):
    return build_context(settings, clock=clock, mailbox=mailbox)


@pytest.fixture
def alice(ctx):
    return ctx.registration.register("alice", "alice@example.test", GOOD_PW, ip_label="t")
