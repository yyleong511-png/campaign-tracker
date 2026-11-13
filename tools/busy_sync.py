#!/usr/bin/env python3
"""Sync team members' busy times (times only, never event details) into the tracker.

  TRACKER_PW=... python3 tools/busy_sync.py members
      Prints JSON: [{"name": ..., "email": ...}] for everyone on the team with an email.

  TRACKER_PW=... python3 tools/busy_sync.py apply busy.json
      busy.json = {"<member name>": {"status": "ok", "blocks": [["<start>", "<end>"], ...]}
                                   | {"status": "no_access"}}
      Start/end are ISO date-times (any offset; converted to Malaysia time) or plain
      dates for all-day busy. For every member listed, their synced blocks for the next
      21 days are replaced. Manually added blocks are kept. Writes straight to the repo
      through the GitHub API with the tracker's own token, so nothing else is needed.
"""
import base64, datetime as dt, json, os, sys, time, urllib.request, urllib.error
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

REPO = "yyleong511-png/campaign-tracker"
PATH = "data.enc.json"
MYT = dt.timezone(dt.timedelta(hours=8))
WINDOW_DAYS = 21
ADMIN_EMAIL = "yyleong511@gmail.com"


def key(pw, salt, it):
    return PBKDF2HMAC(hashes.SHA256(), 32, salt, it).derive(pw.encode())


def api(method, token, body=None):
    req = urllib.request.Request(f"https://api.github.com/repos/{REPO}/contents/{PATH}" + ("?ref=main" if method == "GET" else ""),
                                 method=method, data=json.dumps(body).encode() if body else None,
                                 headers={"Authorization": "Bearer " + token, "Accept": "application/vnd.github+json",
                                          "X-GitHub-Api-Version": "2022-11-28", "User-Agent": "campaign-tracker-sync"})
    with urllib.request.urlopen(req, timeout=60) as r:
        return json.load(r)


def fetch_public():
    url = f"https://raw.githubusercontent.com/{REPO}/main/{PATH}?t={int(time.time())}"
    with urllib.request.urlopen(url, timeout=60) as r:
        return json.load(r)


def decrypt(enc, pw):
    return json.loads(AESGCM(key(pw, base64.b64decode(enc["salt"]), enc["iter"]))
                      .decrypt(base64.b64decode(enc["iv"]), base64.b64decode(enc["ct"]), None))


def encrypt(d, enc, pw):
    iv = os.urandom(12)
    ct = AESGCM(key(pw, base64.b64decode(enc["salt"]), enc["iter"])).encrypt(iv, json.dumps(d, ensure_ascii=False).encode(), None)
    return {"v": enc.get("v", 1), "iter": enc["iter"], "salt": enc["salt"], "iv": base64.b64encode(iv).decode(), "ct": base64.b64encode(ct).decode()}


def members(d):
    out = []
    for m in d.get("team", []):
        if not m.get("name"):
            continue
        email = m.get("email") or (ADMIN_EMAIL if m.get("admin") else "")
        if email:
            out.append({"name": m["name"], "email": email})
    return out


def to_local(s):
    """ISO date-time -> aware datetime in Malaysia time; plain date -> start of that day."""
    if len(s) == 10:
        return dt.datetime.fromisoformat(s).replace(tzinfo=MYT)
    x = dt.datetime.fromisoformat(s.replace("Z", "+00:00"))
    if x.tzinfo is None:
        x = x.replace(tzinfo=MYT)
    return x.astimezone(MYT)


def split_days(start, end):
    """Cut a busy range into per-day pieces: (date, 'HH:MM', 'HH:MM'); 24:00 marks the end of a day."""
    pieces = []
    cur = start
    while cur < end:
        day_end = (cur + dt.timedelta(days=1)).replace(hour=0, minute=0, second=0, microsecond=0)
        stop = min(end, day_end)
        pieces.append((cur.date().isoformat(), cur.strftime("%H:%M"), "24:00" if stop == day_end else stop.strftime("%H:%M")))
        cur = stop
    return pieces


def apply(d, busy, now):
    today = now.date()
    first, last = today, today + dt.timedelta(days=WINDOW_DAYS)
    team = {m["name"] for m in d.get("team", []) if m.get("name")}
    keep = []
    for b in d.get("busy", []):
        day = dt.date.fromisoformat(b["date"])
        if day < today - dt.timedelta(days=1):
            continue  # drop old blocks
        if b.get("src") == "google" and b.get("who") in busy and busy[b["who"]].get("status") == "ok":
            continue  # replaced below
        keep.append(b)
    added = 0
    sync = d.setdefault("busySync", {})
    for name, info in busy.items():
        if name not in team:
            continue
        if info.get("status") != "ok":
            sync[name] = {"status": info.get("status", "error"), "at": now.isoformat(timespec="minutes")}
            continue
        seen = set()
        for s, e in info.get("blocks", []):
            a, b = to_local(s), to_local(e)
            if len(e) == 10 and len(s) == 10 and b <= a:
                b = a + dt.timedelta(days=1)
            for day, hs, he in split_days(a, b):
                if not (first.isoformat() <= day <= last.isoformat()) or hs == he or (day, hs, he) in seen:
                    continue
                seen.add((day, hs, he))
                keep.append({"who": name, "date": day, "start": hs, "end": he, "src": "google"})
                added += 1
        sync[name] = {"status": "ok", "at": now.isoformat(timespec="minutes")}
    keep.sort(key=lambda b: (b["date"], b["start"], b["who"]))
    d["busy"] = keep
    return added


def main():
    pw = os.environ["TRACKER_PW"]
    mode = sys.argv[1]
    if mode == "members":
        print(json.dumps(members(decrypt(fetch_public(), pw)), ensure_ascii=False, indent=2))
        return
    if mode != "apply":
        sys.exit("mode must be members or apply")
    busy = json.load(open(sys.argv[2], encoding="utf8"))
    for attempt in range(3):
        enc0 = decrypt(fetch_public(), pw)
        token = enc0.get("submitToken")
        if not token:
            sys.exit("Team updates are off in the tracker, so there is no token to save with.")
        file = api("GET", token)
        enc = json.loads(base64.b64decode(file["content"]))
        d = decrypt(enc, pw)
        now = dt.datetime.now(MYT)
        n = apply(d, busy, now)
        out = encrypt(d, enc, pw)
        try:
            api("PUT", token, {"message": "Sync busy times", "sha": file["sha"], "branch": "main",
                               "content": base64.b64encode(json.dumps(out).encode()).decode()})
            print(json.dumps({"saved_blocks": n, "members": {k: v.get("status") for k, v in busy.items()}}))
            return
        except urllib.error.HTTPError as e:
            if e.code in (409, 422) and attempt < 2:
                time.sleep(2)
                continue
            raise


if __name__ == "__main__":
    main()
