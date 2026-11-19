"""Unit tests for cedar_client's circuit breaker state machine — direct,
deterministic verification of the open/half-open/closed transitions,
complementing the live check in benchmarks/fail_closed.py (stop
cedar-sidecar, confirm requests fail closed and fast, restart it, confirm
recovery)."""

from app import cedar_client


def _reset_breaker():
    cedar_client._breaker.consecutive_failures = 0
    cedar_client._breaker.opened_at = None
    cedar_client._breaker.trial_in_flight = False


def test_breaker_starts_closed():
    _reset_breaker()
    assert cedar_client._breaker_allow_request() is True


def test_breaker_opens_after_threshold_consecutive_failures():
    _reset_breaker()
    for _ in range(cedar_client._BREAKER_FAILURE_THRESHOLD - 1):
        cedar_client._breaker_record_network_failure()
        assert cedar_client._breaker_allow_request() is True  # not yet at threshold

    cedar_client._breaker_record_network_failure()  # this one crosses the threshold
    assert cedar_client._breaker_allow_request() is False


def test_success_resets_failure_count_before_threshold_is_reached():
    _reset_breaker()
    for _ in range(cedar_client._BREAKER_FAILURE_THRESHOLD - 1):
        cedar_client._breaker_record_network_failure()

    cedar_client._breaker_record_success()
    assert cedar_client._breaker.consecutive_failures == 0

    # One more failure now shouldn't be enough to trip it — the streak
    # that mattered was reset by the success above.
    cedar_client._breaker_record_network_failure()
    assert cedar_client._breaker_allow_request() is True


def test_breaker_half_opens_after_recovery_window_elapses(monkeypatch):
    _reset_breaker()
    for _ in range(cedar_client._BREAKER_FAILURE_THRESHOLD):
        cedar_client._breaker_record_network_failure()
    assert cedar_client._breaker_allow_request() is False

    fake_now = [cedar_client._breaker.opened_at]

    def fake_monotonic():
        return fake_now[0]

    monkeypatch.setattr(cedar_client.time, "monotonic", fake_monotonic)

    fake_now[0] += cedar_client._BREAKER_RECOVERY_SECONDS - 0.01
    assert cedar_client._breaker_allow_request() is False  # cooldown not yet elapsed

    fake_now[0] += 0.02
    assert cedar_client._breaker_allow_request() is True  # half-open: trial request allowed


def test_success_after_half_open_fully_closes_breaker():
    _reset_breaker()
    for _ in range(cedar_client._BREAKER_FAILURE_THRESHOLD):
        cedar_client._breaker_record_network_failure()
    assert cedar_client._breaker_allow_request() is False

    cedar_client._breaker_record_success()
    assert cedar_client._breaker.consecutive_failures == 0
    assert cedar_client._breaker.opened_at is None
    assert cedar_client._breaker_allow_request() is True


def test_half_open_admits_exactly_one_concurrent_trial(monkeypatch):
    """Regression test: a plain time-based check alone (no claim/lock)
    would let every concurrent caller past the cooldown treat itself as
    the trial request, reproducing the exact request pile-up the breaker
    exists to prevent. Only the first caller past the cooldown should be
    admitted; the rest must still fail fast until that trial resolves."""
    _reset_breaker()
    for _ in range(cedar_client._BREAKER_FAILURE_THRESHOLD):
        cedar_client._breaker_record_network_failure()

    fake_now = [cedar_client._breaker.opened_at + cedar_client._BREAKER_RECOVERY_SECONDS + 0.01]
    monkeypatch.setattr(cedar_client.time, "monotonic", lambda: fake_now[0])

    admitted = [cedar_client._breaker_allow_request() for _ in range(10)]
    assert admitted.count(True) == 1
    assert admitted.count(False) == 9


def test_failed_half_open_trial_reopens_with_a_fresh_cooldown_not_the_stale_one(monkeypatch):
    """After a half-open trial fails, the very next caller must NOT
    immediately be treated as past-cooldown again just because the
    original (now long-elapsed) opened_at timestamp was left in place —
    the failed trial needs to restart the cooldown clock."""
    _reset_breaker()
    for _ in range(cedar_client._BREAKER_FAILURE_THRESHOLD):
        cedar_client._breaker_record_network_failure()

    fake_now = [cedar_client._breaker.opened_at + cedar_client._BREAKER_RECOVERY_SECONDS + 0.01]
    monkeypatch.setattr(cedar_client.time, "monotonic", lambda: fake_now[0])

    assert cedar_client._breaker_allow_request() is True  # the one trial
    cedar_client._breaker_record_network_failure()  # ...which fails

    # Same instant, no time has passed — must NOT be immediately re-admitted.
    assert cedar_client._breaker_allow_request() is False

    # Only after a fresh full cooldown from the failed trial does the
    # next one get admitted.
    fake_now[0] += cedar_client._BREAKER_RECOVERY_SECONDS + 0.01
    assert cedar_client._breaker_allow_request() is True
