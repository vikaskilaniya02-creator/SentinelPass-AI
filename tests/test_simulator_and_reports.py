import json

from reports.security_report import build_report, collect_stats, write_html, write_json
from simulator.security_simulator import SecuritySimulator, evaluation_metrics
from tests.conftest import GOOD_PW


def test_metrics_math():
    m = evaluation_metrics([(True, True), (True, False), (False, True), (False, False), (False, False)])
    assert (m["true_positives"], m["false_positives"], m["false_negatives"], m["true_negatives"]) == (1, 1, 1, 2)
    assert m["precision"] == 0.5 and m["recall"] == 0.5 and m["false_positive_rate"] == 0.333


def test_simulator_runs_locally_and_detects_brute_force(settings):
    sim = SecuritySimulator(settings, fast=True)
    out = sim.run("BRUTE_FORCE_SIMULATION")
    sc = out["scenarios"][0]
    assert sc["generated_events"] == 20 and sc["detected_suspicious"] >= 15 and sc["highest_risk"] >= 50
    assert settings.simulation_results_path.exists()


def test_all_scenarios_and_report(settings):
    sim = SecuritySimulator(settings, fast=True)
    out = sim.run()
    assert len(out["scenarios"]) == 7 and out["metrics"]["events"] > 30
    rep = build_report(sim.ctx)
    assert rep["detector_evaluation"]["metrics"]["events"] == out["metrics"]["events"]
    j, h = write_json(rep, settings.report_dir), write_html(rep, settings.report_dir)
    assert json.loads(j.read_text())["system_overview"]["total_users"] >= 7
    assert "<script" not in h.read_text().lower()
    assert "password_hash" not in j.read_text()


def test_stats_password_buckets(ctx, alice):
    s = collect_stats(ctx)
    assert s["total_users"] == 1 and s["strong_password_pct"] == 100.0 and s["accounts_requiring_update"] == []
    ctx.auth.login("alice", GOOD_PW)
    assert collect_stats(ctx)["successful_logins"] == 1
