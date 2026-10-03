import json

from . import db

# Keys that must never reach the audit log even if passed by mistake.
_FORBIDDEN = {"profile", "key", "private_key", "password", "password_hash", "token"}


def log(actor, action, target_type=None, target_id=None, target_label=None, ip=None, **details):
    clean = {k: v for k, v in details.items() if k not in _FORBIDDEN}
    db.ex("INSERT INTO audit_logs(ts, actor, action, target_type, target_id, target_label, details, ip) "
          "VALUES (?,?,?,?,?,?,?,?)",
          db.now_iso(), actor, action, target_type, target_id, target_label, json.dumps(clean, default=str), ip)
