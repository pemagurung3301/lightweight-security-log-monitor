"""Tests for modules/threshold_engine.py"""
import pytest

from modules.threshold_engine import ThresholdEngine

CFG = {"thresholds": {"failed_login_count": 5,
                      "failed_login_window_seconds": 180,
                      "alert_cooldown_seconds": 3}}


def ev(ip="1.2.3.4", user="root", **kw):
    return {"type": "failed_login", "source_ip": ip, "username": user,
            "os": "linux", **kw}


class FakeClock:
    """Lets a test drive time instead of waiting for it."""
    def __init__(self, start=1_000_000.0):
        self.now = start

    def __call__(self):
        return self.now

    def advance(self, seconds):
        self.now += seconds


@pytest.fixture
def clock(monkeypatch):
    fake = FakeClock()
    monkeypatch.setattr("modules.threshold_engine.time.time", fake)
    return fake


# ── threshold behaviour ──────────────────────────────────────
def test_alert_fires_on_the_fifth_failure(clock):
    engine = ThresholdEngine(CFG, verbose=False)
    alerts = []
    for _ in range(5):
        alerts.append(engine.process_event(ev()))
        clock.advance(1)
    assert [a for a in alerts if a] == alerts[-1:]        # only the last one
    assert alerts[-1]["type"] == "brute_force_detected"
    assert alerts[-1]["failure_count"] == 5


def test_four_failures_do_not_alert(clock):
    engine = ThresholdEngine(CFG, verbose=False)
    assert all(engine.process_event(ev()) is None for _ in range(4))
    assert engine.total_alerts == 0


def test_failures_are_counted_per_ip(clock):
    engine = ThresholdEngine(CFG, verbose=False)
    for _ in range(4):
        engine.process_event(ev(ip="1.1.1.1"))
        engine.process_event(ev(ip="2.2.2.2"))
        clock.advance(1)
    assert engine.total_alerts == 0


def test_window_expiry_resets_the_count(clock):
    engine = ThresholdEngine(CFG, verbose=False)
    for _ in range(4):
        engine.process_event(ev())
        clock.advance(1)
    clock.advance(181)                                    # outside the 180s window
    for _ in range(4):
        assert engine.process_event(ev()) is None
    assert engine.total_alerts == 0


def test_one_alert_per_attack_then_realert_after_cooldown(clock):
    engine = ThresholdEngine(CFG, verbose=False)
    results = [engine.process_event(ev()) for _ in range(7)]
    assert sum(1 for r in results if r) == 1              # 7 failures -> 1 alert

    clock.advance(10)                                     # > cooldown (3s)
    alert = engine.process_event(ev())
    assert alert is not None
    assert alert["failure_count"] == 8
    assert engine.total_alerts == 2


def test_alert_message_lists_the_usernames_tried(clock):
    engine = ThresholdEngine(CFG, verbose=False)
    alert = None
    for user in ("root", "admin", "oracle", "root", "postgres"):
        alert = engine.process_event(ev(user=user)) or alert
        clock.advance(1)
    assert alert is not None
    assert sorted(alert["usernames"]) == ["admin", "oracle", "postgres", "root"]
    assert "admin" in alert["message"]


def test_non_failed_login_events_are_ignored(clock):
    engine = ThresholdEngine(CFG, verbose=False)
    assert engine.process_event({"type": "success", "source_ip": "1.2.3.4"}) is None
    assert engine.total_failures == 0


def test_stale_ips_are_pruned(clock, monkeypatch):
    engine = ThresholdEngine(CFG, verbose=False)
    for _ in range(3):
        engine.process_event(ev())
    assert engine.get_stats()["active_ips"]
    clock.advance(100_000)                                # long time later
    engine.process_event(ev(ip="9.9.9.9"))                # triggers the sweep
    assert list(engine._failure_log.keys()) == ["9.9.9.9"]


# ── stats for the GUI ────────────────────────────────────────
def test_stats_snapshot_shape(clock):
    engine = ThresholdEngine(CFG, verbose=False)
    for _ in range(6):
        engine.process_event(ev())
        clock.advance(1)
    stats = engine.get_stats()
    assert stats["max_failures"] == 5
    assert stats["total_failures"] == 6
    assert stats["total_alerts"] == 1
    assert stats["active_ips"][0]["source_ip"] == "1.2.3.4"
    assert stats["active_ips"][0]["breached"] is True


def test_defaults_are_used_when_config_is_empty():
    engine = ThresholdEngine({}, verbose=False)
    assert engine.max_failures == 5
    assert engine.window_secs == 180
