"""Operator tool for contact-form messages (data/contact_messages.jsonl, or $CONTACT_FILE).

    python tools/contact_admin.py list                    # who wrote, when (no message text)
    python tools/contact_admin.py show you@example.com    # everything held for one address
    python tools/contact_admin.py delete you@example.com  # erase one person's messages on request
    python tools/contact_admin.py purge                   # delete messages older than CONTACT_RETENTION_DAYS (also automatic)

Run it on the server that holds the file. It prints nothing it does not need to: `list` omits message text.
"""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from detection.contact_store import ContactStore  # noqa: E402
from detection.settings import load_settings  # noqa: E402


def main(argv=None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    settings = load_settings()
    path = os.getenv("CONTACT_FILE", str(ROOT / "data" / "contact_messages.jsonl"))
    store = ContactStore(path, retention_days=settings.contact_retention_days, max_bytes=settings.contact_max_bytes)
    cmd = argv[0] if argv else ""
    if cmd == "list":
        for r in store.records():
            print(f"{r['at']}  {r.get('name', '')}  <{r.get('email', '')}>")
        return 0
    if cmd == "show" and len(argv) == 2:
        mine = [r for r in store.records() if str(r.get("email", "")).lower() == argv[1].strip().lower()]
        print(json.dumps(mine, indent=2, ensure_ascii=False))
        return 0
    if cmd == "delete" and len(argv) == 2:
        print(f"Deleted {store.delete_by_email(argv[1])} message(s).")
        return 0
    if cmd == "purge":
        print(f"Deleted {store.purge_expired()} expired message(s).")
        return 0
    print(__doc__.strip(), file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main())
