"""vpnpanel-admin — local administration CLI (run on the server).

  vpnpanel-admin create-admin <username>     create an admin (prompts for password)
  vpnpanel-admin reset-password <username>   set a new password, sign out all sessions
  vpnpanel-admin disable-admin <username>
  vpnpanel-admin list-admins
  vpnpanel-admin adopt <cn> --member NAME [--type ADULT|CHILD|GUEST] [--name "Display name"] [--panel]
  vpnpanel-admin apply                       push the full state to OpenVPN / nftables / AdGuard
"""
import argparse
import getpass
import sys

from . import audit, db, engine, security


def _prompt_password(username):
    for _ in range(3):
        pw = getpass.getpass("New password: ")
        problems = security.password_problems(pw, username)
        if problems:
            print("Password needs: " + ", ".join(problems))
            continue
        if getpass.getpass("Repeat password: ") != pw:
            print("Passwords do not match.")
            continue
        return pw
    sys.exit("Giving up.")


def main(argv=None):
    ap = argparse.ArgumentParser(prog="vpnpanel-admin", description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    for name in ("create-admin", "reset-password", "disable-admin"):
        sub.add_parser(name).add_argument("username")
    sub.add_parser("list-admins")
    sub.add_parser("apply")
    a = sub.add_parser("adopt")
    a.add_argument("cn")
    a.add_argument("--member", required=True)
    a.add_argument("--type", default="ADULT", choices=["ADULT", "CHILD", "GUEST"])
    a.add_argument("--name", default="")
    a.add_argument("--panel", action="store_true", help="allow this device to open the admin panel")
    args = ap.parse_args(argv)
    db.init()

    if args.cmd == "create-admin":
        if db.q1("SELECT 1 FROM admins WHERE username = ?", args.username):
            sys.exit("Admin already exists (use reset-password).")
        pw = _prompt_password(args.username)
        db.ex("INSERT INTO admins(username, password_hash, created_at) VALUES (?,?,?)",
              args.username, security.hash_password(pw), db.now_iso())
        audit.log("cli", "admin.created", target_label=args.username)
        print(f"Admin '{args.username}' created.")
    elif args.cmd == "reset-password":
        row = db.q1("SELECT * FROM admins WHERE username = ?", args.username)
        if not row:
            sys.exit("No such admin.")
        pw = _prompt_password(args.username)
        db.ex("UPDATE admins SET password_hash = ?, enabled = 1 WHERE id = ?", security.hash_password(pw), row["id"])
        security.destroy_all_sessions(row["id"])
        db.ex("DELETE FROM login_attempts WHERE username = ? COLLATE NOCASE", args.username)
        audit.log("cli", "admin.password_reset", target_label=args.username)
        print("Password updated; all sessions signed out; lockout cleared.")
    elif args.cmd == "disable-admin":
        row = db.q1("SELECT * FROM admins WHERE username = ?", args.username)
        if not row:
            sys.exit("No such admin.")
        db.ex("UPDATE admins SET enabled = 0 WHERE id = ?", row["id"])
        security.destroy_all_sessions(row["id"])
        audit.log("cli", "admin.disabled", target_label=args.username)
        print("Admin disabled.")
    elif args.cmd == "list-admins":
        for r in db.q("SELECT username, enabled, created_at, last_login_at FROM admins ORDER BY id"):
            print(f"{r['username']:20} {'enabled' if r['enabled'] else 'DISABLED':9} created {r['created_at']}  "
                  f"last login {r['last_login_at'] or 'never'}")
    elif args.cmd == "adopt":
        m = db.q1("SELECT * FROM family_members WHERE name = ?", args.member)
        if not m:
            default = {"ADULT": "Adult — unrestricted", "CHILD": "Child — standard", "GUEST": "Guest"}[args.type]
            pid = db.q1("SELECT id FROM policies WHERE name = ?", default)["id"]
            cur = db.ex("INSERT INTO family_members(name, type, policy_id, created_at) VALUES (?,?,?,?)",
                        args.member, args.type, pid, db.now_iso())
            m = db.q1("SELECT * FROM family_members WHERE id = ?", cur.lastrowid)
            audit.log("cli", "member.created", "member", m["id"], m["name"], type=args.type)
        did = engine.adopt_certificate(args.cn, m["id"], args.name or args.cn, args.panel, "cli", None)
        d = db.q1("SELECT * FROM devices WHERE id = ?", did)
        print(f"Adopted {args.cn} as device #{did} ({d['vpn_ipv4']}) for {m['name']}.")
    elif args.cmd == "apply":
        pushed, errors = engine.apply(force=True)
        print("pushed:", ", ".join(pushed) or "nothing")
        if errors:
            sys.exit("errors: " + "; ".join(errors))


if __name__ == "__main__":
    main()
