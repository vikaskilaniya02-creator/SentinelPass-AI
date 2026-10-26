"""Statistics collection + JSON/HTML security report (shared with the dashboard)."""
from __future__ import annotations

import html
import json
from pathlib import Path

from app_context import AppContext
from audit.audit_logger import EventType
from utils import iso

STRONG_SCORE, WEAK_SCORE = 65, 40


def collect_stats(ctx: AppContext) -> dict:
    now = ctx.clock()
    users = ctx.users.list_all()
    logins = ctx.login_events.stats()
    by_type = ctx.security_events.count_by_type()
    total = len(users) or 1
    strong = sum(1 for u in users if u.password_score >= STRONG_SCORE)
    weak = [u for u in users if u.password_score < WEAK_SCORE]
    dist = logins["risk_distribution"]
    return {
        "total_users": len(users),
        "active_users": sum(1 for u in users if u.is_active),
        "locked_accounts": sum(1 for u in users if u.is_locked(now)),
        "successful_logins": logins["successful"],
        "failed_logins": logins["failed"],
        "suspicious_logins": dist["MEDIUM"] + dist["HIGH"] + dist["CRITICAL"],
        "reset_requests": by_type.get(EventType.PASSWORD_RESET_REQUESTED, 0),
        "rate_limit_triggers": by_type.get(EventType.RATE_LIMIT_TRIGGERED, 0),
        "risk_distribution": dist,
        "strong_password_pct": round(100 * strong / total, 1),
        "weak_password_pct": round(100 * len(weak) / total, 1),
        "accounts_requiring_update": [u.username for u in weak],
        "password_reuse_detections": by_type.get(EventType.PASSWORD_REUSE_BLOCKED, 0),
    }


def _row(r) -> dict:
    return {k: r[k] for k in r.keys()}


def build_report(ctx: AppContext) -> dict:
    stats = collect_stats(ctx)
    ai = ctx.risk_explainer.summarize_security(stats)
    suspicious = [_row(r) for r in ctx.login_events.suspicious(10)]
    results_path = ctx.settings.simulation_results_path
    evaluation = None
    if results_path.is_file():
        evaluation = json.loads(results_path.read_text(encoding="utf-8"))
    return {
        "generated_at": iso(ctx.clock()),
        "system_overview": {"app_env": ctx.settings.app_env, "ai_provider": ctx.settings.ai_provider,
                            "total_users": stats["total_users"], "active_users": stats["active_users"],
                            "locked_accounts": stats["locked_accounts"]},
        "authentication_statistics": {k: stats[k] for k in
                                      ("successful_logins", "failed_logins", "suspicious_logins",
                                       "reset_requests", "rate_limit_triggers")},
        "risk_distribution": stats["risk_distribution"],
        "password_security": {k: stats[k] for k in
                              ("strong_password_pct", "weak_password_pct",
                               "accounts_requiring_update", "password_reuse_detections")},
        "suspicious_activity": suspicious,
        "recent_security_events": [{"timestamp": r["timestamp"], "event_type": r["event_type"],
                                    "severity": r["severity"], "user_id": r["user_id"]}
                                   for r in ctx.security_events.recent(20)],
        "ai_analysis": {**ai.to_dict(), "note": "AI explains and recommends; it never makes security decisions."},
        "detected_anomalies": [e for e in suspicious if (e.get("risk_score") or 0) >= 50],
        "security_recommendations": ai.recommendations + [
            "Add MFA/passkeys.", "Move rate limiting to a shared store before production.",
            "Check passwords against a breached-password corpus."],
        "detector_evaluation": evaluation,
    }


def write_json(report: dict, directory: str | Path) -> Path:
    path = Path(directory) / "security_report.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    return path


def _table(rows: list[dict], cols: list[str]) -> str:
    head = "".join(f"<th>{html.escape(c)}</th>" for c in cols)
    body = "".join("<tr>" + "".join(f"<td>{html.escape(str(r.get(c, '')))}</td>" for c in cols) + "</tr>" for r in rows)
    return f"<table><tr>{head}</tr>{body}</table>"


def write_html(report: dict, directory: str | Path) -> Path:
    e = html.escape
    kv = lambda d: "<ul>" + "".join(f"<li><b>{e(str(k))}</b>: {e(str(v))}</li>" for k, v in d.items()) + "</ul>"
    ai = report["ai_analysis"]
    parts = [
        "<!doctype html><html><head><meta charset='utf-8'><title>SentinelPass AI Security Report</title>",
        "<style>body{font-family:system-ui,sans-serif;max-width:900px;margin:2rem auto;padding:0 1rem;color:#1a1a1a}"
        "table{border-collapse:collapse;width:100%}td,th{border:1px solid #ccc;padding:4px 8px;font-size:.9rem}"
        "h2{border-bottom:2px solid #264653;padding-bottom:4px}</style></head><body>",
        f"<h1>SentinelPass AI - Security Report</h1><p>Generated {e(report['generated_at'])}</p>",
        "<h2>System overview</h2>" + kv(report["system_overview"]),
        "<h2>Authentication statistics</h2>" + kv(report["authentication_statistics"]),
        "<h2>Risk distribution</h2>" + kv(report["risk_distribution"]),
        "<h2>Password security</h2>" + kv(report["password_security"]),
        "<h2>Suspicious activity</h2>" + _table(report["suspicious_activity"],
                                                ["timestamp", "username_attempted", "risk_score", "risk_level", "reason"]),
        f"<h2>AI security analysis ({e(ai['source'])})</h2><p><b>{e(ai['risk'])}</b>: {e(ai['explanation'])}</p>"
        f"<p><i>{e(ai['note'])}</i></p>",
        "<h2>Recommendations</h2><ul>" + "".join(f"<li>{e(r)}</li>" for r in report["security_recommendations"]) + "</ul>",
    ]
    ev = report.get("detector_evaluation")
    if ev:
        parts.append("<h2>Detector evaluation (synthetic data)</h2>" + kv(ev.get("metrics", {})))
    parts.append("</body></html>")
    path = Path(directory) / "security_report.html"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("".join(parts), encoding="utf-8")
    return path
