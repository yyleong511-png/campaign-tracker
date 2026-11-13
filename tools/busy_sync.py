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

  TRACKER_PW=... python3 tools/busy_sync.py shots /tmp/shots
      Downloads and decrypts the calendar screenshots members uploaded ("I'm busy" →
      Upload a screenshot) into that folder. Prints JSON: today's date and
      [{"id", "who", "file"}] for each screenshot waiting to be read.

  TRACKER_PW=... python3 tools/busy_sync.py applyshots result.json
      result.json = {"<screenshot id>": {"status": "ok", "blocks": [[start, end], ...]}
                                       | {"status": "unreadable"}}
      Start/end: "YYYY-MM-DDTHH:MM" (Malaysia time) or plain dates for all-day.
      Adds the busy times for that member, marks the screenshot read and deletes the
      encrypted image from the repo. Only times are ever saved.
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


def api(method, token, body=None, path=PATH):
    req = urllib.request.Request(f"https://api.github.com/repos/{REPO}/contents/{path}" + ("?ref=main" if method == "GET" else ""),
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


def fetch_raw(path):
    with urllib.request.urlopen(f"https://raw.githubusercontent.com/{REPO}/main/{path}?t={int(time.time())}", timeout=120) as r:
        return r.read()


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


def apply_shots(d, res, now):
    """Add busy blocks read from screenshots. Returns list of (path, sha) to delete."""
    today = now.date()
    first, last = today - dt.timedelta(days=1), today + dt.timedelta(days=90)
    shots = {x["id"]: x for x in d.get("busyShots", [])}
    busy = d.setdefault("busy", [])
    have = {(b["who"], b["date"], b["start"], b["end"]) for b in busy}
    gone = []
    for sid, info in res.items():
        sh = shots.get(sid)
        if not sh or sh.get("status") != "pending":
            continue
        n = 0
        if info.get("status") == "ok":
            for s, e in info.get("blocks", []):
                a, b = to_local(s), to_local(e)
                if len(e) == 10 and len(s) == 10 and b <= a:
                    b = a + dt.timedelta(days=1)
                for day, hs, he in split_days(a, b):
                    k = (sh["who"], day, hs, he)
                    if not (first.isoformat() <= day <= last.isoformat()) or hs == he or k in have:
                        continue
                    have.add(k)
                    busy.append({"who": sh["who"], "date": day, "start": hs, "end": he, "src": "shot", "shot": sid})
                    n += 1
            sh["status"], sh["n"] = "done", n
        else:
            sh["status"] = "unreadable"
        sh["readAt"] = now.isoformat(timespec="minutes")
        if sh.get("path"):
            gone.append((sh.pop("path"), sh.pop("sha", None)))
    # keep only the last 10 notes per person
    per = {}
    for x in reversed(d.get("busyShots", [])):
        per.setdefault(x["who"], []).append(x)
    d["busyShots"] = [x for x in d.get("busyShots", []) if x["status"] == "pending" or x in per[x["who"]][:10]]
    busy.sort(key=lambda b: (b["date"], b["start"], b["who"]))
    return gone


def save(pw, mutate, message):
    for attempt in range(3):
        enc0 = decrypt(fetch_public(), pw)
        token = enc0.get("submitToken")
        if not token:
            sys.exit("Team updates are off in the tracker, so there is no token to save with.")
        file = api("GET", token)
        enc = json.loads(base64.b64decode(file["content"]))
        d = decrypt(enc, pw)
        result = mutate(d)
        out = encrypt(d, enc, pw)
        try:
            api("PUT", token, {"message": message, "sha": file["sha"], "branch": "main",
                               "content": base64.b64encode(json.dumps(out).encode()).decode()})
            return token, result
        except urllib.error.HTTPError as e:
            if e.code in (409, 422) and attempt < 2:
                time.sleep(2)
                continue
            raise


def main():
    pw = os.environ["TRACKER_PW"]
    mode = sys.argv[1]
    if mode == "members":
        print(json.dumps(members(decrypt(fetch_public(), pw)), ensure_ascii=False, indent=2))
        return
    if mode == "shots":
        folder = sys.argv[2]
        os.makedirs(folder, exist_ok=True)
        enc = fetch_public()
        d = decrypt(enc, pw)
        k = key(pw, base64.b64decode(enc["salt"]), enc["iter"])
        out = []
        for x in d.get("busyShots", []):
            if x.get("status") != "pending" or not x.get("path"):
                continue
            try:
                blob = fetch_raw(x["path"])
                img = AESGCM(k).decrypt(blob[:12], blob[12:], None)
            except Exception as e:
                out.append({"id": x["id"], "who": x["who"], "file": None, "error": str(e)[:80]})
                continue
            ext = {"image/png": ".png", "image/jpeg": ".jpg", "image/heic": ".heic", "image/webp": ".webp"}.get(x.get("mime", ""), ".png")
            f = os.path.join(folder, x["id"] + ext)
            open(f, "wb").write(img)
            out.append({"id": x["id"], "who": x["who"], "file": f, "uploaded": x.get("at")})
        print(json.dumps({"today": dt.datetime.now(MYT).date().isoformat(), "screenshots": out}, ensure_ascii=False, indent=2))
        return
    if mode == "applyshots":
        res = json.load(open(sys.argv[2], encoding="utf8"))
        now = dt.datetime.now(MYT)
        token, gone = save(pw, lambda d: apply_shots(d, res, now), "Read calendar screenshots")
        for path, sha in gone:
            try:
                if not sha:
                    sha = api("GET", token, path=path)["sha"]
                api("DELETE", token, {"message": "Delete read screenshot", "sha": sha, "branch": "main"}, path=path)
            except Exception as e:
                print("could not delete", path, e, file=sys.stderr)
        print(json.dumps({"read": list(res.keys()), "deleted": len(gone)}))
        return
    if mode != "apply":
        sys.exit("mode must be members, apply, shots or applyshots")
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
