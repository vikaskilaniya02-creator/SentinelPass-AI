"""CLI menu. Calls services only; contains no authentication logic."""
from __future__ import annotations

import hashlib
import logging
import platform
from typing import Callable

from app_context import AppContext
from cli import prompts as ui
from exceptions import (AccountLockedError, PasswordPolicyError, RateLimitExceededError,
                        SentinelPassError)
from reports.security_report import build_report, collect_stats, write_html, write_json
from simulator.security_simulator import SecuritySimulator, print_results

log = logging.getLogger("sentinelpass")
DEVICE_ID = "cli-" + hashlib.sha256(platform.node().encode()).hexdigest()[:8]  # stable local label, not PII


class Menu:
    def __init__(self, ctx: AppContext) -> None:
        self.ctx = ctx
        self.session_token: str | None = None
        self.username: str | None = None

    # ---- error handling: users only ever see generic messages ----
    def _safe(self, fn: Callable[[], None]) -> None:
        try:
            fn()
        except PasswordPolicyError as exc:
            ui.error(str(exc))
            for reason in exc.details.get("reasons", []):
                ui.info(f"- {reason}")
        except RateLimitExceededError as exc:
            ui.error(f"{exc} (retry in ~{exc.details.get('retry_after', '?')}s)")
        except SentinelPassError as exc:
            ui.error(str(exc))
        except (KeyboardInterrupt, EOFError):
            print()
        except Exception:  # technical detail goes to the log file, never to the screen
            log.exception("Unhandled error")
            ui.error("Unexpected error. Details were written to the error log.")

    # ---- actions ----
    def register(self) -> None:
        user = ui.ask("Username: ")
        email = ui.ask("Email: ")
        pw = ui.ask_secret("Password: ")
        if pw != ui.ask_secret("Confirm password: "):
            return ui.error("Passwords do not match.")
        self.ctx.registration.register(user, email, pw, ip_label="LOCAL")
        ui.info("Account created.")

    def login(self) -> None:
        user, pw = ui.ask("Username: "), ui.ask_secret("Password: ")
        kw = dict(device_id=DEVICE_ID, ip_label="LOCAL", user_agent_label="cli")
        res = self.ctx.auth.login(user, pw, **kw)
        if res.status == "STEP_UP_REQUIRED":
            ui.info(res.message)
            ui.info(f"DEMO ONLY - verification code (a real system sends this out-of-band): {res.demo_step_up_code}")
            res = self.ctx.auth.login(user, pw, step_up_code=ui.ask("Verification code: "), **kw)
        if res.status == "SUCCESS":
            self.session_token, self.username = res.session_token, user.strip().lower()
            ui.info(f"Welcome, {self.username}. Session started (risk {res.risk.score}/100 {res.risk.level}).")
        else:
            ui.error(res.message)
        if res.risk and res.risk.level != "LOW":
            ai = self.ctx.risk_explainer.explain_login(res.risk)
            ui.info(f"AI explanation [{ai.source}]: {ai.explanation}")

    def check_password(self) -> None:
        pw = ui.ask_secret("Password to check (stays on this machine): ")
        result = self.ctx.policy.evaluate(pw)
        d = result.to_dict()
        ui.info(f"Score: {d['score']}/100  Rating: {d['rating']}  Risk: {d['risk_level']}  Entropy~{d['estimated_entropy']} bits")
        for w in d["warnings"]:
            ui.info(f"warning: {w}")
        for r in d["recommendations"]:
            ui.info(f"tip: {r}")
        ai = self.ctx.password_ai.analyze(result)  # only derived features leave this function
        ui.info(f"\nAI Security Assessment [{ai.source}] Risk: {ai.risk}\n  {ai.explanation}")
        for r in ai.recommendations:
            ui.info(f"* {r}")
        ui.info(d["disclaimer"])

    def change_password(self) -> None:
        user = self.username or ui.ask("Username: ")
        cur = ui.ask_secret("Current password: ")
        new = ui.ask_secret("New password: ")
        if new != ui.ask_secret("Confirm new password: "):
            return ui.error("Passwords do not match.")
        self.ctx.auth.change_password(user, cur, new, ip_label="LOCAL")
        self.session_token, self.username = None, None
        ui.info("Password changed. All sessions were signed out; please log in again.")

    def forgot_password(self) -> None:
        ident = ui.ask("Username or email: ")
        self.ctx.reset.request_reset(ident, ip_label="LOCAL")
        # Same message whether or not the account exists (prevents account enumeration).
        ui.info("If that account exists, a reset message has been sent.")
        ui.info(f"DEMO ONLY: there is no real email. Open {self.ctx.settings.mailbox_path} to read the demo mailbox.")
        if ui.ask("Do you have a reset token to use now? (y/N): ").lower() == "y":
            token = ui.ask_secret("Reset token: ")
            new = ui.ask_secret("New password: ")
            self.ctx.reset.reset_password(token, new, ip_label="LOCAL")
            ui.info("Password reset successful. Please log in.")

    def dashboard(self) -> None:
        s = collect_stats(self.ctx)
        ui.banner("SECURITY DASHBOARD (text)")
        for k in ("total_users", "active_users", "locked_accounts", "successful_logins", "failed_logins",
                  "suspicious_logins", "reset_requests", "strong_password_pct", "weak_password_pct"):
            ui.info(f"{k:22}: {s[k]}")
        ui.info(f"risk distribution     : {s['risk_distribution']}")
        ui.info("For charts run:  streamlit run dashboard.py")

    def events(self) -> None:
        ui.banner("RECENT LOGIN EVENTS")
        ui.table([[r["timestamp"][:19], r["username_attempted"], "OK" if r["success"] else "FAIL",
                   r["risk_level"] or "-", r["reason"]] for r in self.ctx.login_events.recent(15)],
                 ["time (UTC)", "user", "result", "risk", "reason"])
        ui.banner("RECENT SECURITY EVENTS")
        ui.table([[r["timestamp"][:19], r["event_type"], r["severity"]] for r in self.ctx.security_events.recent(15)],
                 ["time (UTC)", "event", "severity"])

    def ai_analysis(self) -> None:
        stats = collect_stats(self.ctx)
        ai = self.ctx.risk_explainer.summarize_security(stats)
        ui.banner("AI SECURITY ANALYST", f"source: {ai.source}")
        ui.info(f"Overall risk: {ai.risk}\n  {ai.explanation}")
        for r in ai.recommendations:
            ui.info(f"* {r}")
        ui.info("AI output is advisory only; deterministic code makes all security decisions.")

    def report(self) -> None:
        rep = build_report(self.ctx)
        ui.info(f"JSON: {write_json(rep, self.ctx.settings.report_dir)}")
        ui.info(f"HTML: {write_html(rep, self.ctx.settings.report_dir)}")

    def simulate(self) -> None:
        ui.info("Running LOCAL synthetic scenarios (no external systems are contacted)...")
        print_results(SecuritySimulator(self.ctx.settings, fast=True).run())

    # ---- main loop ----
    def run(self) -> None:
        actions = {"1": self.register, "2": self.login, "3": self.check_password, "4": self.change_password,
                   "5": self.forgot_password, "6": self.dashboard, "7": self.events,
                   "8": self.ai_analysis, "9": self.report, "10": self.simulate}
        while True:
            ui.banner("SENTINELPASS AI", "Password & Authentication Security")
            if self.username:
                ui.info(f"(logged in as {self.username})")
            for n, label in enumerate(["Register", "Login", "Check Password", "Change Password", "Forgot Password",
                                       "Security Dashboard", "Security Events", "AI Security Analysis",
                                       "Generate Security Report", "Run Security Simulation", "Exit"], 1):
                print(f"  {n}. {label}")
            choice = ui.ask("\nSelect: ")
            if choice == "11":
                return print("Goodbye.")
            action = actions.get(choice)
            if action:
                self._safe(action)
            else:
                ui.error("Invalid option.")
