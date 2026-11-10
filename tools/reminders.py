#!/usr/bin/env python3
"""List the deadline reminder emails due today (Malaysia time). Sends nothing itself.

  TRACKER_PW=... python3 tools/reminders.py data.enc.json [YYYY-MM-DD]

Prints JSON: [{"to": [...], "subject": "...", "body": "..."}]
A task is due on its deadline, or on its end date for start -> end tasks.
Reminders go 7, 3 and 1 day(s) before, to the assigned members' emails.
Tasks marked Done are skipped. Tasks with no assignee (or no emails) go to the admins.
"""
import base64, datetime as dt, json, os, sys
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

SITE = "https://yyleong511-png.github.io/campaign-tracker/"
ADMIN_FALLBACK = "yyleong511@gmail.com"
LEADS = {7: "in 1 week", 3: "in 3 days", 1: "tomorrow"}
MYT = dt.timezone(dt.timedelta(hours=8))


def load(path, pw):
    e = json.load(open(path))
    key = PBKDF2HMAC(hashes.SHA256(), 32, base64.b64decode(e["salt"]), e["iter"]).derive(pw.encode())
    return json.loads(AESGCM(key).decrypt(base64.b64decode(e["iv"]), base64.b64decode(e["ct"]), None))


def fmt_time(hm):
    h, m = map(int, hm.split(":"))
    return f"{(h % 12) or 12}:{m:02d} {'am' if h < 12 else 'pm'}"


def main():
    d = load(sys.argv[1], os.environ["TRACKER_PW"])
    today = dt.date.fromisoformat(sys.argv[2]) if len(sys.argv) > 2 else dt.datetime.now(MYT).date()
    team = d.get("team", [])
    emails = {m["name"]: m["email"] for m in team if m.get("name") and m.get("email")}
    admins = [m["email"] for m in team if m.get("admin") and m.get("email")] or [ADMIN_FALLBACK]
    out = []
    for t in d.get("tasks", []):
        if "done" in (t.get("status") or "").lower():
            continue
        if t.get("start") and t.get("end"):
            due, hm = t["end"], t.get("endTime") or "23:59"
        elif t.get("deadline"):
            due, hm = t["deadline"], t.get("time") or "23:59"
        else:
            continue
        lead = (dt.date.fromisoformat(due) - today).days
        if lead not in LEADS:
            continue
        names = t.get("assignees") or ([t["owner"]] if t.get("owner") else [])
        to = sorted({emails[n] for n in names if n in emails}) or admins
        when = dt.date.fromisoformat(due).strftime("%a, %d %b %Y").replace(" 0", " ") + ", " + fmt_time(hm)
        lines = [f"Reminder: \"{t['task']}\" is due {LEADS[lead]}.", "", f"Due: {when}"]
        if t.get("start") and t.get("end"):
            lines.append("Started: " + dt.date.fromisoformat(t["start"]).strftime("%a, %d %b").replace(" 0", " "))
        if names:
            lines.append("Assigned: " + ", ".join(names))
        if t.get("status"):
            lines.append("Status: " + t["status"])
        if t.get("notes"):
            lines += ["", t["notes"]]
        lines += ["", "Campaign Tracker: " + SITE, "", "This is an automatic reminder. Mark the task Done in the tracker to stop reminders."]
        out.append({"to": to, "subject": f"Reminder: {t['task']} due {LEADS[lead]} ({when.split(',')[1].strip()})", "body": "\n".join(lines)})
    print(json.dumps(out, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
