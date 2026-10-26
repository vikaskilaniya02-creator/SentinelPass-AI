"""Security event simulator.

Runs ONLY against the local application database (synthetic `sim_*` accounts,
fake region/device labels). It never touches the network or any external system.
Each event carries a ground-truth label so the detector can be EVALUATED
(precision / recall / false-positive rate) instead of just claimed to work.

    python -m simulator.security_simulator [--full] [--scenario NAME]
"""
from __future__ import annotations

import argparse
import json
import secrets
from dataclasses import dataclass, field, replace
from datetime import timedelta

from app_context import AppContext, build_context
from auth.password_reset import ListMailbox
from config.settings import Settings, load_settings
from exceptions import RateLimitExceededError, SentinelPassError
from utils import ManualClock, utcnow

DEMO_PASSWORD = "Correct-Horse-Battery-9!"
HOME = {"device": "dev-home", "ip": "IN-RJ", "ua": "desktop-browser"}
SCENARIOS = ["NORMAL_LOGIN", "BRUTE_FORCE_SIMULATION", "NEW_DEVICE_LOGIN", "UNUSUAL_TIME_LOGIN",
             "RAPID_LOGIN_SEQUENCE", "PASSWORD_RESET_ABUSE", "MULTIPLE_FAILED_LOGINS"]


@dataclass
class ScenarioResult:
    name: str
    generated_events: int = 0
    detected_suspicious: int = 0
    highest_risk: int | None = None
    recommended_action: str = "None"
    labels: list[tuple[bool, bool]] = field(default_factory=list)  # (truly_malicious, flagged)

    def to_dict(self) -> dict:
        d = self.__dict__.copy()
        d["labels"] = [list(x) for x in self.labels]
        return d


def evaluation_metrics(pairs: list[tuple[bool, bool]]) -> dict:
    tp = sum(1 for m, p in pairs if m and p)
    fp = sum(1 for m, p in pairs if not m and p)
    fn = sum(1 for m, p in pairs if m and not p)
    tn = sum(1 for m, p in pairs if not m and not p)
    div = lambda a, b: round(a / b, 3) if b else 0.0
    precision, recall = div(tp, tp + fp), div(tp, tp + fn)
    return {"events": len(pairs), "true_positives": tp, "false_positives": fp,
            "false_negatives": fn, "true_negatives": tn, "precision": precision, "recall": recall,
            "false_positive_rate": div(fp, fp + tn),
            "f1": div(2 * precision * recall, precision + recall) if precision + recall else 0.0}


class SecuritySimulator:
    def __init__(self, settings: Settings, fast: bool = True) -> None:
        if fast:  # fewer PBKDF2 rounds ONLY for synthetic accounts, to keep the demo quick
            settings = replace(settings, password_hash_iterations=20_000)
        self.clock = ManualClock()
        self.mailbox = ListMailbox()
        self.ctx: AppContext = build_context(settings, clock=self.clock, mailbox=self.mailbox)
        self.today = self.clock().replace(hour=0, minute=0, second=0, microsecond=0)

    # -------- helpers --------
    def _at(self, hour: int, minute: int = 0) -> None:
        self.clock.set(self.today + timedelta(hours=hour, minutes=minute))

    def _new_user(self, tag: str) -> str:
        self.clock.advance(minutes=15)
        self.ctx.rate_limiter.reset()  # each scenario starts with clean limiter state (simulated time jumps around)
        username = f"sim_{tag}_{secrets.token_hex(2)}"
        self.ctx.registration.register(username, f"{username}@example.test", DEMO_PASSWORD, ip_label="sim-reg")
        return username

    def _baseline(self, username: str) -> None:
        """Five normal daytime logins on previous days => the user's 'normal' pattern."""
        for i in range(5, 0, -1):
            self.clock.set(self.today - timedelta(days=i) + timedelta(hours=10, minutes=i * 7))
            self.ctx.auth.login(username, DEMO_PASSWORD, device_id=HOME["device"], ip_label=HOME["ip"],
                                user_agent_label=HOME["ua"])

    def _attempt(self, res: ScenarioResult, username: str, password: str, malicious: bool, *,
                 device: str = HOME["device"], ip: str = HOME["ip"], ua: str = HOME["ua"]) -> None:
        flagged = False
        try:
            self.ctx.auth.login(username, password, device_id=device, ip_label=ip, user_agent_label=ua)
        except RateLimitExceededError:
            flagged = True  # blocked by the rate limiter = detected
        except SentinelPassError:
            pass
        last = self.ctx.login_events.recent(1)[0]
        if last["risk_level"] in ("MEDIUM", "HIGH", "CRITICAL"):
            flagged = True
        if last["risk_score"] is not None:
            res.highest_risk = max(res.highest_risk or 0, last["risk_score"])
        self._tally(res, malicious, flagged)

    @staticmethod
    def _tally(res: ScenarioResult, malicious: bool, flagged: bool) -> None:
        res.generated_events += 1
        res.detected_suspicious += int(flagged)
        res.labels.append((malicious, flagged))

    def _finish(self, res: ScenarioResult) -> ScenarioResult:
        score = res.highest_risk or 0
        res.recommended_action = ("Lock account and raise security event" if score >= 75 else
                                  "Temporary account restriction" if score >= 50 else
                                  "Require additional verification" if score >= 25 else
                                  "Rate-limit and monitor" if res.detected_suspicious else "None")
        return res

    # -------- scenarios --------
    def normal_login(self) -> ScenarioResult:
        res, user = ScenarioResult("NORMAL_LOGIN"), self._new_user("normal")
        self._baseline(user)
        self._at(11)
        for _ in range(5):
            self._attempt(res, user, DEMO_PASSWORD, False)
            self.clock.advance(hours=1)
        return self._finish(res)

    def brute_force(self) -> ScenarioResult:
        res, user = ScenarioResult("BRUTE_FORCE_SIMULATION"), self._new_user("brute")
        self._baseline(user)
        self._at(14)
        for i in range(20):
            self._attempt(res, user, f"wrong-guess-{i}", True, device="attacker-dev", ip="EXT-REGION-1", ua="script")
            self.clock.advance(seconds=1)
        return self._finish(res)

    def new_device(self) -> ScenarioResult:
        res, user = ScenarioResult("NEW_DEVICE_LOGIN"), self._new_user("newdev")
        self._baseline(user)
        self._at(15)
        self._attempt(res, user, DEMO_PASSWORD, True, device="dev-unknown", ip="IN-MH", ua="mobile-app")
        return self._finish(res)

    def unusual_time(self) -> ScenarioResult:
        res, user = ScenarioResult("UNUSUAL_TIME_LOGIN"), self._new_user("night")
        self._baseline(user)
        self._at(3)
        self._attempt(res, user, DEMO_PASSWORD, True, device="dev-unknown", ip=HOME["ip"], ua=HOME["ua"])
        return self._finish(res)

    def rapid_sequence(self) -> ScenarioResult:
        res, user = ScenarioResult("RAPID_LOGIN_SEQUENCE"), self._new_user("rapid")
        self._baseline(user)
        self._at(12)
        for _ in range(3):
            self._attempt(res, user, DEMO_PASSWORD, False)
            self.clock.advance(seconds=20)
        self.clock.advance(minutes=2)  # same account, far-away region two minutes later
        self._attempt(res, user, DEMO_PASSWORD, True, device="dev-foreign", ip="US-NY", ua="desktop-browser")
        return self._finish(res)

    def reset_abuse(self) -> ScenarioResult:
        res, user = ScenarioResult("PASSWORD_RESET_ABUSE"), self._new_user("reset")
        self._at(12)
        for _ in range(6):
            before = len(self.mailbox.messages)
            flagged = False
            try:
                self.ctx.reset.request_reset(user, ip_label="EXT-REGION-2")
            except RateLimitExceededError:
                flagged = True
            self._tally(res, True, flagged or len(self.mailbox.messages) == before)
            self.clock.advance(seconds=5)
        res.highest_risk = None  # detection here is rate-limit based, not score based
        return self._finish(res)

    def multiple_failed(self) -> ScenarioResult:
        res, user = ScenarioResult("MULTIPLE_FAILED_LOGINS"), self._new_user("typo")
        self._baseline(user)
        self._at(15)
        for i in range(4):  # a real user who forgot their password (benign)
            self._attempt(res, user, f"forgot-{i}", False)
            self.clock.advance(seconds=30)
        self._attempt(res, user, DEMO_PASSWORD, False)
        return self._finish(res)

    def run(self, only: str | None = None) -> dict:
        runners = {"NORMAL_LOGIN": self.normal_login, "BRUTE_FORCE_SIMULATION": self.brute_force,
                   "NEW_DEVICE_LOGIN": self.new_device, "UNUSUAL_TIME_LOGIN": self.unusual_time,
                   "RAPID_LOGIN_SEQUENCE": self.rapid_sequence, "PASSWORD_RESET_ABUSE": self.reset_abuse,
                   "MULTIPLE_FAILED_LOGINS": self.multiple_failed}
        names = [only] if only else SCENARIOS
        results = [runners[n]() for n in names]
        pairs = [p for r in results for p in r.labels]
        payload = {"scenarios": [r.to_dict() for r in results], "metrics": evaluation_metrics(pairs),
                   "note": "Synthetic data, local only. Metrics describe THIS simulation, not real-world accuracy."}
        path = self.ctx.settings.simulation_results_path
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        return payload


def print_results(payload: dict) -> None:
    for r in payload["scenarios"]:
        hr = f"{r['highest_risk']}/100" if r["highest_risk"] is not None else "n/a (rate-limit based)"
        print(f"\nScenario:\n{r['name']}\n\nGenerated events:\n{r['generated_events']}\n\n"
              f"Detected suspicious events:\n{r['detected_suspicious']}\n\nHighest risk:\n{hr}\n\n"
              f"Recommended action:\n{r['recommended_action']}\n" + "-" * 44)
    m = payload["metrics"]
    print("\nDETECTOR EVALUATION (synthetic, labelled events)")
    print(f"  events={m['events']}  precision={m['precision']}  recall={m['recall']}  "
          f"false-positive-rate={m['false_positive_rate']}  f1={m['f1']}")
    print(f"  TP={m['true_positives']} FP={m['false_positives']} FN={m['false_negatives']} TN={m['true_negatives']}")
    print("  " + payload["note"])


def main() -> None:
    parser = argparse.ArgumentParser(description="Local-only security event simulator")
    parser.add_argument("--full", action="store_true", help="use the configured (slow) hash iterations")
    parser.add_argument("--scenario", choices=SCENARIOS)
    args = parser.parse_args()
    sim = SecuritySimulator(load_settings(), fast=not args.full)
    print_results(sim.run(args.scenario))


if __name__ == "__main__":
    main()
