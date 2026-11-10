#!/usr/bin/env python3
"""Encrypt / decrypt the tracker data.

  TRACKER_PW=... python3 tools/crypt.py enc data.json data.enc.json
  TRACKER_PW=... python3 tools/crypt.py dec data.enc.json data.json

The plain data.json and the password never go into this repository.
PBKDF2-SHA256 (600k iterations) -> AES-256-GCM. The salt is kept across
updates so phones that already unlocked the site stay unlocked.
"""
import base64, json, os, sys
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

ITER = 600_000
b64 = lambda b: base64.b64encode(b).decode()
unb64 = base64.b64decode


def key(pw, salt, it=ITER):
    return PBKDF2HMAC(hashes.SHA256(), 32, salt, it).derive(pw.encode())


def main():
    mode, src, dst = sys.argv[1:4]
    pw = os.environ["TRACKER_PW"]
    if mode == "enc":
        plain = json.dumps(json.load(open(src, encoding="utf8")), ensure_ascii=False).encode()
        salt = os.urandom(16)
        if os.path.exists(dst):
            salt = unb64(json.load(open(dst))["salt"])
        iv = os.urandom(12)
        ct = AESGCM(key(pw, salt)).encrypt(iv, plain, None)
        json.dump({"v": 1, "iter": ITER, "salt": b64(salt), "iv": b64(iv), "ct": b64(ct)}, open(dst, "w"))
    elif mode == "dec":
        e = json.load(open(src))
        plain = AESGCM(key(pw, unb64(e["salt"]), e["iter"])).decrypt(unb64(e["iv"]), unb64(e["ct"]), None)
        open(dst, "wb").write(plain)
    else:
        sys.exit("mode must be enc or dec")


if __name__ == "__main__":
    main()
