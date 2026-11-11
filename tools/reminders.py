#!/usr/bin/env python3
"""List the reminder emails due today (Malaysia time). Sends nothing itself.

  TRACKER_PW=... python3 tools/reminders.py data.enc.json [YYYY-MM-DD]

Prints JSON: [{"to": [...], "subject": "...", "body": "..."}]
Reminders go 7, 3 and 1 day(s) before:
  - tasks: their deadline (or end date for start -> end tasks), to the assignees; Done tasks skipped
  - shoots: the shoot date, to the team crew
  - brands: the next follow-up date, to whoever follows up; Confirmed / Declined skipped
  - meetings: the meeting date and time, to the team members attending
Anything with no one (or no emails) goes to the admins.
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


def fmt_day(iso):
    return dt.date.fromisoformat(iso).strftime("%a, %d %b %Y").replace(" 0", " ")


def main():
    d = load(sys.argv[1], os.environ["TRACKER_PW"])
    today = dt.date.fromisoformat(sys.argv[2]) if len(sys.argv) > 2 else dt.datetime.now(MYT).date()
    team = d.get("team", [])
    emails = {m["name"]: m["email"] for m in team if m.get("name") and m.get("email")}
    admins = [m["email"] for m in team if m.get("admin") and m.get("email")] or [ADMIN_FALLBACK]
    out = []

    def add(kind, title, due, hm, names, details):
        lead = (dt.date.fromisoformat(due) - today).days
        if lead not in LEADS:
            return
        to = sorted({emails[n] for n in names if n in emails}) or admins
        when = fmt_day(due) + ", " + fmt_time(hm)
        first = {"Task": f"Reminder: \"{title}\" is due {LEADS[lead]}.",
                 "Shoot": f"Reminder: the shoot \"{title}\" is {LEADS[lead]}.",
                 "Follow-up": f"Reminder: follow up with {title} {LEADS[lead]}.",
                 "Meeting": f"Reminder: the meeting \"{title}\" is {LEADS[lead]}."}[kind]
        lines = [first, "",
                 ("Due: " if kind == "Task" else "When: ") + when]
        lines += [x for x in details if x]
        lines += ["", "Campaign Tracker: " + SITE, "", "This is an automatic reminder from the Campaign Tracker."]
        label = {"Task": f"{title} due", "Shoot": f"Shoot: {title}", "Follow-up": f"Follow up with {title}", "Meeting": f"Meeting: {title}"}[kind]
        out.append({"to": to, "subject": f"Reminder: {label} {LEADS[lead]} ({fmt_day(due)[5:]})", "body": "\n".join(lines)})

    for t in d.get("tasks", []):
        if "done" in (t.get("status") or "").lower():
            continue
        if t.get("start") and t.get("end"):
            due, hm = t["end"], t.get("endTime") or "23:59"
        elif t.get("deadline"):
            due, hm = t["deadline"], t.get("time") or "23:59"
        else:
            continue
        names = t.get("assignees") or ([t["owner"]] if t.get("owner") else [])
        add("Task", t["task"], due, hm, names, [
            "Assigned: " + ", ".join(names) if names else "",
            "Status: " + t["status"] if t.get("status") else "",
            "\n" + t["notes"] if t.get("notes") else "",
            "\nMark the task Done in the tracker to stop reminders."])

    for s in d.get("shoots", []):
        if not s.get("date"):
            continue
        names = s.get("people") or []
        st = s.get("time") or "09:00"
        add("Shoot", s.get("project", "Shoot"), s["date"], st, names, [
            "Until: " + fmt_time(s["endTime"]) if s.get("endTime") else "",
            "Location: " + s["location"] if s.get("location") else "",
            "Crew: " + ", ".join(names + ([s["crew"]] if s.get("crew") else [])) if (names or s.get("crew")) else "",
            "\n" + s["notes"] if s.get("notes") else ""])

    for m in d.get("meetings", []):
        if not m.get("date"):
            continue
        names = m.get("people") or []
        add("Meeting", m.get("title", "Meeting"), m["date"], m.get("time") or "09:00", names, [
            "Until: " + fmt_time(m["endTime"]) if m.get("endTime") else "",
            "Location: " + m["location"] if m.get("location") else "",
            "Attending: " + ", ".join(names + ([m["others"]] if m.get("others") else [])) if (names or m.get("others")) else "",
            "\n" + m["notes"] if m.get("notes") else ""])

    for b in d.get("outreach", []):
        if not b.get("next") or (b.get("status") or "") in ("Confirmed", "Declined"):
            continue
        names = b.get("followBy") or []
        add("Follow-up", b.get("brand", "brand"), b["next"], b.get("nextTime") or "23:59", names, [
            "Contact: " + b["contact"] if b.get("contact") else "",
            "Status: " + b["status"] if b.get("status") else "",
            "Follow-up by: " + ", ".join(names) if names else "",
            "\n" + b["notes"] if b.get("notes") else ""])

    print(json.dumps(out, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
