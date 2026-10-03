"""Time-window evaluation. The server runs on UTC; every window is stored with an
IANA timezone and evaluated in that zone, so DST changes are handled by zoneinfo."""
import re
from datetime import datetime, timedelta, timezone
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError, available_timezones

DAY_NAMES = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"]
WEEKDAYS = [0, 1, 2, 3, 4]
WEEKEND = [5, 6]
HHMM = re.compile(r"^([01]\d|2[0-3]):([0-5]\d)$")

# A sensible default for policies with "enforce schedule" when no schedule is configured.
DEFAULT_WINDOWS = [
    {"days": WEEKDAYS, "start": "06:30", "end": "21:30"},
    {"days": WEEKEND, "start": "07:30", "end": "22:30"},
]


def valid_tz(name):
    try:
        ZoneInfo(name)
        return True
    except (ZoneInfoNotFoundError, ValueError):
        return False


_TZ_CACHE = None


def timezones():
    global _TZ_CACHE
    if _TZ_CACHE is None:
        _TZ_CACHE = sorted(t for t in available_timezones() if "/" in t and not t.startswith(("Etc/", "SystemV/"))) + ["UTC"]
    return _TZ_CACHE


def minutes(hhmm):
    m = HHMM.match(hhmm or "")
    if not m:
        raise ValueError(f"invalid time {hhmm!r}")
    return int(m.group(1)) * 60 + int(m.group(2))


def in_window(local_dt, days, start, end):
    """True if local_dt falls in [start, end) on one of `days`.
    Windows with end <= start run past midnight (e.g. 21:00–06:30)."""
    s, e = minutes(start), minutes(end)
    t = local_dt.hour * 60 + local_dt.minute
    wd = local_dt.weekday()
    if s < e:
        return wd in days and s <= t < e
    if s == e:  # full day
        return wd in days
    return (wd in days and t >= s) or (((wd - 1) % 7) in days and t < e)


def allowed_by_windows(windows, tz, now=None):
    now = now or datetime.now(timezone.utc)
    local = now.astimezone(ZoneInfo(tz))
    return any(in_window(local, w["days"], w["start"], w["end"]) for w in windows)


def next_change(windows, tz, now=None, horizon_hours=72):
    """When the allowed/blocked state flips next (minute resolution), or None."""
    now = (now or datetime.now(timezone.utc)).replace(second=0, microsecond=0)
    cur = allowed_by_windows(windows, tz, now)
    t = now
    for _ in range(horizon_hours * 60):
        t += timedelta(minutes=1)
        if allowed_by_windows(windows, tz, t) != cur:
            return t
    return None


def describe(windows):
    out = []
    for w in windows:
        days = sorted(w["days"])
        if days == WEEKDAYS:
            label = "Weekdays"
        elif days == WEEKEND:
            label = "Weekends"
        elif days == list(range(7)):
            label = "Every day"
        else:
            label = ", ".join(DAY_NAMES[d] for d in days)
        out.append(f"{label} {w['start']}–{w['end']}")
    return "; ".join(out) or "No allowed hours"
