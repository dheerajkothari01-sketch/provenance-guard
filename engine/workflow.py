r"""
Hold-queue workflow with a two-person rule and an append-only audit trail.

    HOLD (or escalated REVIEW):
        open --callback(accountant)--> callback_confirmed --release(manager, different person)--> released
                                    \-> callback_failed
        any open state --block(manager or IT security)--> blocked
    REVIEW:
        open --clear--> cleared        open --escalate--> escalated (then follows the HOLD path)

Rules enforced here (not just in the UI):
  * only the roles in auth.ROLES may take each action
  * nobody may act on a change they made themselves
  * the person who releases must not be the person who recorded the call-back
  * a change can only be released after a confirmed call-back
"""
import json
import threading
from datetime import datetime, timezone
from pathlib import Path

from .auth import ROLES, can

_LOCK = threading.RLock()  # re-entrant: a refusal logged while the queue is locked must not deadlock

STATUS_TEXT = {
    "open": "Waiting for call-back",
    "open_review": "Needs review",
    "escalated": "Escalated: waiting for call-back",
    "callback_confirmed": "Call-back confirmed: waiting for Finance Manager",
    "callback_failed": "Call-back FAILED: block recommended",
    "released": "Released",
    "blocked": "Blocked as fraud",
    "cleared": "Cleared after review",
}
FINAL = {"released", "blocked", "cleared"}
ACTION_TEXT = {"callback": "record a call-back", "release": "release a change", "block": "block a change",
               "clear": "clear a review", "escalate": "escalate a review"}


def now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


class Workflow:
    def __init__(self, state_dir: Path, dataset_id: str):
        self.dir = Path(state_dir)
        self.dir.mkdir(parents=True, exist_ok=True)
        self.dataset = dataset_id
        self.qfile = self.dir / f"queue_{dataset_id}.json"
        self.afile = self.dir / "audit_log.jsonl"

    # ------------------------------------------------------------ storage
    def _load(self) -> dict:
        return json.loads(self.qfile.read_text()) if self.qfile.exists() else {}

    def _save(self, q: dict):
        tmp = self.qfile.with_suffix(".tmp")
        tmp.write_text(json.dumps(q, indent=1))
        tmp.replace(self.qfile)

    def log(self, user, action, change_id="", detail="", result="ok"):
        rec = dict(time=now(), user=(user or {}).get("username", "-"), name=(user or {}).get("name", "-"),
                   role=ROLES.get((user or {}).get("role"), {}).get("title", "-"), action=action,
                   change_id=change_id, result=result, detail=detail, dataset=self.dataset)
        with _LOCK, self.afile.open("a") as f:
            f.write(json.dumps(rec) + "\n")

    def audit(self) -> list[dict]:
        if not self.afile.exists():
            return []
        return [json.loads(x) for x in self.afile.read_text().splitlines() if x.strip()]

    def record(self, change_id) -> dict:
        return self._load().get(change_id, {})

    def all(self) -> dict:
        return self._load()

    # ------------------------------------------------------------ helpers
    @staticmethod
    def status_of(rec: dict, decision: str) -> str:
        st = rec.get("status", "open")
        return "open_review" if (st == "open" and decision == "REVIEW") else st

    def _deny(self, user, action, cid, why):
        self.log(user, action, cid, why, result="denied")
        return False, why

    def _act(self, user, action, change, new_status, note, need, allowed_from, extra=None):
        cid = change["change_id"]
        if not can(user, need):
            return self._deny(user, action, cid, f"Your role ({ROLES[user['role']]['title']}) can't {ACTION_TEXT.get(action, action)}.")
        if user["username"] == str(change.get("changed_by", "")).lower():
            return self._deny(user, action, cid, "You made this change, so you can't act on it.")
        with _LOCK:
            q = self._load()
            rec = q.get(cid, {"status": "open"})
            if rec["status"] not in allowed_from:
                why = f"Not allowed while the change is '{STATUS_TEXT.get(rec['status'], rec['status'])}'."
            elif extra:
                why = extra(rec)
            else:
                why = None
            if why:
                return self._deny(user, action, cid, why)
            rec.update(status=new_status, **{f"{action}_by": user["username"], f"{action}_name": user["name"],
                                             f"{action}_at": now(), f"{action}_note": note})
            q[cid] = rec
            self._save(q)
        self.log(user, action, cid, note or STATUS_TEXT[new_status])
        return True, STATUS_TEXT[new_status]

    # ------------------------------------------------------------ actions
    def callback(self, user, change, confirmed: bool, note=""):
        def check(rec):
            if rec.get("status", "open") == "open" and change.get("decision") != "HOLD":
                return "This change is only flagged for review. Escalate it first if it needs a call-back."
            return None
        return self._act(user, "callback", change, "callback_confirmed" if confirmed else "callback_failed",
                         note or ("Vendor confirmed the new details" if confirmed else "Vendor did NOT confirm"),
                         "callback", {"open", "escalated"}, check)

    def release(self, user, change, note=""):
        def check(rec):
            if rec.get("callback_by") == user["username"]:
                return "Two-person rule: you recorded the call-back, so someone else must release it."
            return None
        return self._act(user, "release", change, "released", note, "release", {"callback_confirmed"}, check)

    def block(self, user, change, note=""):
        return self._act(user, "block", change, "blocked", note, "block",
                         {"open", "escalated", "callback_confirmed", "callback_failed"})

    @staticmethod
    def _review_only(change):
        return lambda rec: None if change.get("decision") == "REVIEW" else \
            "Only changes flagged for REVIEW can be cleared or escalated. Held changes need a call-back."

    def clear(self, user, change, note=""):
        return self._act(user, "clear", change, "cleared", note or "Reviewed: looks legitimate", "clear", {"open"},
                         self._review_only(change))

    def escalate(self, user, change, note=""):
        return self._act(user, "escalate", change, "escalated", note or "Escalated to hold", "escalate", {"open"},
                         self._review_only(change))

    def reset(self, user):
        with _LOCK:
            if self.qfile.exists():
                self.qfile.unlink()
        self.log(user, "reset demo queue", "", "all queue decisions cleared")
