"""Host metrics from /proc (no extra dependencies)."""
import os
import time

from . import config, helper

_cpu_prev = None
_health = {"ts": 0, "data": None}


def _cpu_times():
    with open("/proc/stat") as f:
        parts = [int(x) for x in f.readline().split()[1:]]
    idle = parts[3] + parts[4]
    return idle, sum(parts)


def cpu_percent():
    global _cpu_prev
    if config.FAKE or not os.path.exists("/proc/stat"):
        return 3.2
    cur = _cpu_times()
    prev = _cpu_prev
    if prev is None:
        time.sleep(0.2)
        prev, cur = cur, _cpu_times()
    _cpu_prev = cur
    didle, dtotal = cur[0] - prev[0], cur[1] - prev[1]
    return round(100.0 * (1 - didle / dtotal), 1) if dtotal else 0.0


def memory():
    if config.FAKE or not os.path.exists("/proc/meminfo"):
        return {"total": 4_000_000_000, "used": 620_000_000, "percent": 15.5}
    info = {}
    with open("/proc/meminfo") as f:
        for line in f:
            k, v = line.split(":")
            info[k] = int(v.split()[0]) * 1024
    used = info["MemTotal"] - info["MemAvailable"]
    return {"total": info["MemTotal"], "used": used, "percent": round(100 * used / info["MemTotal"], 1)}


def disk(path="/"):
    if config.FAKE:
        return {"total": 25_000_000_000, "used": 4_100_000_000, "percent": 16.4}
    st = os.statvfs(path)
    total = st.f_blocks * st.f_frsize
    free = st.f_bavail * st.f_frsize
    return {"total": total, "used": total - free, "percent": round(100 * (total - free) / total, 1)}


def uptime_seconds():
    if config.FAKE or not os.path.exists("/proc/uptime"):
        return 266_000
    with open("/proc/uptime") as f:
        return float(f.read().split()[0])


def loadavg():
    if config.FAKE:
        return (0.08, 0.05, 0.01)
    try:
        return os.getloadavg()
    except OSError:
        return (0, 0, 0)


def health(max_age=20):
    if _health["data"] is None or time.time() - _health["ts"] > max_age:
        try:
            _health["data"] = helper.health()
        except Exception as e:  # noqa: BLE001
            _health["data"] = {"ok": False, "error": str(e), "services": {}}
        _health["ts"] = time.time()
    return _health["data"]


def snapshot():
    return {"cpu": cpu_percent(), "mem": memory(), "disk": disk(), "uptime": uptime_seconds(),
            "load": loadavg(), "health": health()}
