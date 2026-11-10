# Campaign Tracker

Private team tracker, served by GitHub Pages and installable to a phone home screen.

- `index.html` — the app. Asks for the team password once per phone, then decrypts and shows the tracker.
- `data.enc.json` — the tracker content, encrypted (AES-256-GCM, key from PBKDF2-SHA256). Unreadable without the team password.
- `sw.js` — caches the app shell only, never the data.
- `tools/crypt.py` — encrypts / decrypts the data. The plain data and the password are never committed here.

To update: decrypt, edit, encrypt, commit `data.enc.json`.
