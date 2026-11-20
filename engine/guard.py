"""
Payment-Run Provenance Guard — detection engine (CR-26-047, Defense).

For every vendor bank-detail change (E19) it rebuilds the change's provenance chain:
    E19 change -> E18/E01 API call (request_id) -> E04 credential -> network (+E15 private link)
               -> E17 indicators -> payment calendar
scores how well the chain holds up, and decides ALLOW / REVIEW / HOLD.

The engine has no UI dependency, so it runs on any folder of files in the case formats.
"""
from __future__ import annotations

import ipaddress
import json
import re
from dataclasses import dataclass, field
from datetime import date, timedelta
from pathlib import Path

import pandas as pd

BANK_FIELD = re.compile(r"bank|acct|^account(?:_?(?:no|num|number))?$|ifsc|iban|swift|bic\b|beneficiary|payee|routing"
                        r"|sort_?code", re.I)
PHONE_FIELD = re.compile(r"phone|mobile|telephone|contact_?(?:no|number)", re.I)
IST = timedelta(hours=5, minutes=30)

# file prefix -> (timestamp column, minutes to ADD to reach UTC, note)
DEFAULT_CLOCKS = {
    "E01": ("ts_utc", 0, "UTC"),
    "E18": ("ts_utc", 0, "UTC"),
    "E19": ("ts_utc", 0, "UTC"),
    "E15": ("ts_utc", 0, "UTC"),
    "E03": ("ts_utc", 0, "UTC"),
    "E02": ("ts_local", -330, "tenant local time, assumed IST (UTC+5:30)"),
    "E05": ("epoch_s", 0, "unsynchronised clock: set the measured offset"),
}

RULES = {
    "no_approval": ("No approval reference on a bank-detail change", 40),
    "machine_change": ("Changed by software (API key), not by a person", 10),
    "off_network": ("Request came from outside the key's expected network", 25),
    "staff_offsite": ("Staff change made from outside the office network", 10),
    "new_behaviour": ("Key has little or no history of approved bank changes", 20),
    "near_run": ("Close to a payment run", 15),
    "watch_window": ("Within a week of a payment run", 5),
    "indicator": ("Matches an outside-company indicator (E17)", 30),
    "mule": ("Same new account given to more than one vendor", 20),
    "log_gap": ("API call for this change is missing from the log", 10),
    "key_scope": ("Key is not allowed to change vendor records, or is disabled (E04)", 30),
    "risky_login": ("Staff sign-in before this change looked risky (E03)", 25),
    "callback_changed": ("Vendor's phone number changed shortly before this bank change", 20),
}
WRITE_SCOPE = re.compile(r"vendors?:\s*write|\*:\s*write|admin|write:\*", re.I)


@dataclass
class Settings:
    hold_threshold: int = 60
    review_threshold: int = 30
    risk_window_days: int = 3
    watch_window_days: int = 7
    payment_days: tuple = (8, 23)
    expected_networks: list = field(default_factory=lambda: ["10.20.4.0/24"])
    internal_networks: list = field(default_factory=lambda: ["172.16.0.0/16"])
    behaviour_min_days: int = 3
    learn_min_share: float = 0.05
    flow_match_minutes: int = 10
    contact_window_days: int = 14
    login_lookback_hours: int = 12
    failed_login_threshold: int = 3
    clock_offsets: dict = field(default_factory=dict)  # prefix -> minutes to add (overrides defaults)
    enabled: dict = field(default_factory=lambda: {k: True for k in RULES})
    weights: dict = field(default_factory=lambda: {k: v[1] for k, v in RULES.items()})


# --------------------------------------------------------------------------- loading
def _prefix(name: str) -> str | None:
    m = re.match(r"(?i)^(E\d{2}|labels)", Path(name).name)
    return m.group(1).upper() if m else None


def _read_any(name: str, data) -> pd.DataFrame:
    """data: path or bytes/file-like."""
    if str(name).lower().endswith(".json"):
        raw = json.loads(Path(data).read_text() if isinstance(data, (str, Path)) else data.read())
        if isinstance(raw, dict):
            raw = next((v for v in raw.values() if isinstance(v, list)), [raw])
        return pd.DataFrame(raw)
    return pd.read_csv(data, dtype=str, keep_default_na=False)


def load_folder(folder: str | Path) -> dict[str, pd.DataFrame]:
    out = {}
    for p in sorted(Path(folder).iterdir()):
        if p.suffix.lower() not in (".csv", ".json"):
            continue
        pre = _prefix(p.name)
        if pre:
            out[pre] = _read_any(p.name, p) if pre not in out else pd.concat([out[pre], _read_any(p.name, p)])
    return out


def load_uploads(files) -> dict[str, pd.DataFrame]:
    """files: iterable of objects with .name and file-like read() (e.g. Streamlit UploadedFile)."""
    out = {}
    for f in files:
        pre = _prefix(f.name)
        if pre:
            df = _read_any(f.name, f)
            out[pre] = df if pre not in out else pd.concat([out[pre], df])
    return out


def normalise_clocks(data: dict[str, pd.DataFrame], settings: Settings):
    """Adds a `ts` (UTC) column to every timed table. Returns (data, clock report)."""
    report = []
    for pre, df in data.items():
        if pre not in DEFAULT_CLOCKS:
            continue
        col, offset, note = DEFAULT_CLOCKS[pre]
        offset = settings.clock_offsets.get(pre, offset)
        if col not in df.columns:
            continue
        if col == "epoch_s":
            ts = pd.to_datetime(pd.to_numeric(df[col], errors="coerce"), unit="s", utc=True)
        else:
            ts = pd.to_datetime(df[col], utc=True, errors="coerce")
        df = df.copy()
        df["ts"] = ts + pd.Timedelta(minutes=offset)
        data[pre] = df
        report.append(dict(file=pre, column=col, basis=note, minutes_added=offset, rows=len(df),
                           unparsed=int(df["ts"].isna().sum())))
    return data, pd.DataFrame(report)


# --------------------------------------------------------------------------- helpers
def _nets(cidrs):
    out = []
    for c in cidrs:
        c = str(c).strip()
        if c:
            try:
                out.append(ipaddress.ip_network(c, strict=False))
            except ValueError:
                pass
    return out


def _in(ip, nets):
    try:
        a = ipaddress.ip_address(str(ip).strip())
    except ValueError:
        return False
    return any(a in n for n in nets)


def _slash24(ip):
    try:
        return str(ipaddress.ip_network(f"{ip}/24", strict=False))
    except ValueError:
        return None


def next_run(ts, payment_days):
    """Next payment-run date on or after the change's India-time date."""
    d = (ts + IST).date()
    for add in range(0, 40):
        c = d + timedelta(days=add)
        if c.day in payment_days:
            return c, add
    return None, None


# --------------------------------------------------------------------------- core
def evaluate(data: dict[str, pd.DataFrame], settings: Settings | None = None):
    s = settings or Settings()
    data = {k: v.copy() for k, v in data.items()}
    data, clocks = normalise_clocks(data, s)
    if "E19" not in data:
        raise ValueError("E19 (vendor record change log) is required")

    e19 = data["E19"].sort_values("ts").reset_index(drop=True)
    api = pd.concat([data[k] for k in ("E01", "E18") if k in data], ignore_index=True) \
        if any(k in data for k in ("E01", "E18")) else pd.DataFrame(columns=["request_id", "api_key_id", "caller_ip",
                                                                             "user_agent", "ts"])
    api = api.drop_duplicates("request_id") if "request_id" in api else api
    by_req = api.set_index("request_id").to_dict("index") if len(api) else {}
    e15 = data.get("E15", pd.DataFrame(columns=["src_ip", "ts", "tunnel_id", "src_label"]))
    e17 = data.get("E17", pd.DataFrame(columns=["indicator", "type", "confidence"]))
    e04 = data.get("E04", pd.DataFrame(columns=["credential_id"]))
    creds = e04.set_index("credential_id").to_dict("index") if len(e04) and "credential_id" in e04 else {}

    ind_map = {str(r["indicator"]).strip(): r for _, r in e17.iterrows()}
    expected_cfg = _nets(s.expected_networks)
    internal = _nets(s.internal_networks)

    # E03 sign-ins, per user (optional)
    e03 = data.get("E03")
    if e03 is not None and "user" in e03:
        e03 = e03.copy()
        e03["user_l"] = e03["user"].astype(str).str.strip().str.lower()
        e03 = e03.sort_values("ts")
    e19["is_bank"] = e19["field"].astype(str).str.contains(BANK_FIELD)
    e19["is_phone"] = e19["field"].astype(str).str.contains(PHONE_FIELD) & ~e19["is_bank"]
    # new accounts reused across vendors
    acct_rows = e19[e19["is_bank"] & e19["field"].str.contains("account|acct|iban", case=False)]
    mule_counts = acct_rows.groupby("new_value")["vendor_id"].nunique().to_dict()

    rows = []
    for _, c in e19.iterrows():
        t = c["ts"]
        reasons, chain = [], []
        score = 0
        safe_callback = ""

        def hit(rule, detail=""):
            nonlocal score
            if s.enabled.get(rule, True):
                w = s.weights.get(rule, RULES[rule][1])
                score += w
                reasons.append(f"{RULES[rule][0]}{(' — ' + detail) if detail else ''} (+{w})")

        actor = str(c.get("changed_by", ""))
        channel = str(c.get("channel", "")).lower()
        approval = str(c.get("approval_ref", "")).strip()
        rid = str(c.get("request_id", "")).strip()
        call = by_req.get(rid) if rid else None
        is_machine = channel == "api" or actor in creds or bool(rid)
        key = (call or {}).get("api_key_id") or (actor if actor in creds else "")
        ip = (call or {}).get("caller_ip") or c.get("source_ip", "")
        ua = (call or {}).get("user_agent", "")
        run_date, days = next_run(t, s.payment_days)

        chain.append(dict(step="E19 change", ok=bool(approval) or not c["is_bank"],
                          detail=f"{c['field']} changed by {actor} via {channel or 'unknown'}; "
                                 f"approval: {approval or 'NONE'}"))

        if c["is_bank"]:
            if not approval:
                hit("no_approval")

            if is_machine:
                hit("machine_change", key)
                if rid and call is None:
                    hit("log_gap", rid)
                    chain.append(dict(step="E18/E01 API call", ok=False, detail=f"{rid} not found in API logs"))
                else:
                    chain.append(dict(step="E18/E01 API call", ok=True,
                                      detail=f"{rid}: {call.get('method', '')} {call.get('endpoint', '')} "
                                             f"from {ip} ({ua})" if call else "no request id"))
                # credential
                cr = creds.get(key)
                if cr:
                    stale = ""
                    try:
                        age = (t.date() - date.fromisoformat(str(cr.get("last_review", ""))[:10])).days
                        stale = f"; last review {age} days ago" if age > 365 else ""
                    except ValueError:
                        pass
                    chain.append(dict(step="E04 credential", ok=not stale and str(cr.get("status")) == "active",
                                      detail=f"{cr.get('integration')} — scope {cr.get('scope')}{stale}"))
                    can_write = bool(WRITE_SCOPE.search(str(cr.get("scope", ""))))
                    if not can_write or str(cr.get("status", "active")).lower() != "active":
                        hit("key_scope", f"{key}: scope '{cr.get('scope')}', status {cr.get('status')}")
                elif len(e04):
                    chain.append(dict(step="E04 credential", ok=False, detail=f"{key or 'unknown key'} not in register"))
                    hit("key_scope", f"{key or 'unknown key'} is not in the register")
                else:
                    chain.append(dict(step="E04 credential", ok=True, detail="register (E04) not loaded"))
                # expected network: register restriction + configured + learned from history
                nets = list(expected_cfg) + _nets(str((cr or {}).get("ip_restriction", "")).split(","))
                if len(api) and key:
                    hist = api[(api["api_key_id"] == key) & (api["ts"] < t)]
                    if len(hist) >= 20:
                        share = hist["caller_ip"].map(_slash24).value_counts(normalize=True)
                        nets += _nets(share[share >= s.learn_min_share].index)
                on_net = _in(ip, nets)
                if not on_net:
                    hit("off_network", str(ip))
                chain.append(dict(step="Network", ok=on_net,
                                  detail=f"{ip} {'is' if on_net else 'is NOT'} in the key's expected network"))
                # E15 corroboration (information only)
                if len(e15) and "src_ip" in e15:
                    win = pd.Timedelta(minutes=s.flow_match_minutes)
                    fl = e15[(e15["src_ip"] == str(ip)) & (e15["ts"].between(t - win, t + win))]
                    chain.append(dict(step="E15 private link", ok=len(fl) > 0,
                                      detail=(f"{len(fl)} tunnel flow(s) from {ip} "
                                              f"labelled '{fl['src_label'].iloc[0]}' (label unverified)")
                                      if len(fl) else f"no private-link traffic from {ip} at that time"))
                # behaviour: has this key made APPROVED bank changes on enough earlier days?
                # (unapproved ones don't count, so earlier attacks can't make the key look normal)
                prior = e19[(e19["changed_by"] == actor) & e19["is_bank"] & (e19["ts"] < t)
                            & (e19["approval_ref"].astype(str).str.strip() != "")]
                if prior["ts"].dt.date.nunique() < s.behaviour_min_days:
                    hit("new_behaviour", f"{prior['ts'].dt.date.nunique()} earlier approved day(s)")
            else:
                chain.append(dict(step="E18/E01 API call", ok=True, detail="not applicable: made in the app by a person"))
                if internal and not _in(ip, internal):
                    hit("staff_offsite", str(ip))
                chain.append(dict(step="Network", ok=_in(ip, internal),
                                  detail=f"{ip} {'office' if _in(ip, internal) else 'outside office (remote?)'}"))
                # E03: how did this person sign in before making the change?
                if e03 is not None and "user_l" in e03:
                    u = actor.strip().lower()
                    look = pd.Timedelta(hours=s.login_lookback_hours)
                    mine = e03[(e03["user_l"] == u) & (e03["ts"] <= t)]
                    win = mine[mine["ts"] >= t - look]
                    ok_ins = win[win["result"].astype(str).str.lower() == "success"]
                    flags = []
                    if not len(ok_ins):
                        flags.append(f"no successful sign-in in the {s.login_lookback_hours} h before")
                    else:
                        last = ok_ins.iloc[-1]
                        before = mine[mine["ts"] < last["ts"] - pd.Timedelta(seconds=1)]
                        before_ok = before[before["result"].astype(str).str.lower() == "success"]
                        dev = str(last.get("device_id", "")).strip()
                        devs = before_ok.get("device_id", pd.Series(dtype=str)).astype(str).str.strip()
                        known_dev = set(devs) - {""}
                        # need real device history: E03's device field can be blank for older rows
                        if dev and (devs != "").sum() >= 3 and dev not in known_dev:
                            flags.append(f"new device {dev}")
                        city = str(last.get("city", "")).strip()
                        known_city = set(before_ok.get("city", pd.Series(dtype=str)).astype(str).str.strip()) - {""}
                        if city and len(before_ok) >= 5 and city not in known_city:
                            flags.append(f"new city {city}")
                        if str(last.get("mfa_result", "")).lower() in ("failed", "bypassed", "not_enrolled"):
                            flags.append(f"MFA {last.get('mfa_result')}")
                        fails = win[(win["result"].astype(str).str.lower() != "success")
                                    & (win["ts"] >= last["ts"] - pd.Timedelta(hours=1))]
                        if len(fails) >= s.failed_login_threshold:
                            flags.append(f"{len(fails)} failed attempts just before")
                    if flags and len(ok_ins):
                        hit("risky_login", ", ".join(flags))
                    chain.append(dict(step="E03 staff sign-in", ok=not flags,
                                      detail=("; ".join(flags) if flags else
                                              f"normal sign-in from {ok_ins.iloc[-1].get('city', '?')} on a known device")
                                      + (f" (last sign-in {ok_ins.iloc[-1]['ts']:%d %b %H:%M} UTC)" if len(ok_ins) else "")))

            # indicators
            matched = [ind_map[x] for x in {str(ip).strip(), str(ua).strip()} if x and x in ind_map]
            if matched:
                hit("indicator", ", ".join(f"{m['indicator']} ({m.get('confidence', '?')})" for m in matched))
            chain.append(dict(step="E17 indicators", ok=not matched,
                              detail="match: " + ", ".join(m["indicator"] for m in matched) if matched
                              else "no match"))
            # mule account
            if re.search("account|acct|iban", str(c["field"]), re.I) and mule_counts.get(c["new_value"], 0) > 1:
                hit("mule", f"{mule_counts[c['new_value']]} vendors")
            # was the vendor's phone (the call-back number) changed shortly before?
            ph = e19[(e19["vendor_id"] == c.get("vendor_id")) & e19["is_phone"] & (e19["ts"] < t)
                     & (e19["ts"] >= t - pd.Timedelta(days=s.contact_window_days))]
            if len(ph):
                first = ph.iloc[0]
                safe_callback = (f"Phone changed {first['ts'] + IST:%d %b} by {first['changed_by']}: call the OLD "
                                 f"number {first['old_value']}, not {ph.iloc[-1]['new_value']}")
                hit("callback_changed", f"{len(ph)} phone change(s) in the {s.contact_window_days} days before")
            else:
                safe_callback = "Phone number on file unchanged in the last " \
                                f"{s.contact_window_days} days: use it for the call-back"
            chain.append(dict(step="Call-back number", ok=not len(ph), detail=safe_callback))
            # payment calendar
            if days is not None and days <= s.risk_window_days:
                hit("near_run", f"{days} day(s) before the {run_date:%d %b} run")
            elif days is not None and days <= s.watch_window_days:
                hit("watch_window", f"{days} days before the {run_date:%d %b} run")
            chain.append(dict(step="Payment calendar", ok=days is None or days > s.risk_window_days,
                              detail=f"next run {run_date:%d %b %Y}, {days} day(s) away" if run_date else "n/a"))

            score = min(score, 100)
            decision = "HOLD" if score >= s.hold_threshold else "REVIEW" if score >= s.review_threshold else "ALLOW"
        else:
            decision = "OUT OF SCOPE"

        rows.append(dict(change_id=c["change_id"], ts_utc=t, ts_ist=(t + IST).strftime("%Y-%m-%d %H:%M"),
                         vendor_id=c.get("vendor_id"), vendor_name=c.get("vendor_name"), field=c["field"],
                         old_value=c.get("old_value"), new_value=c.get("new_value"), changed_by=actor,
                         channel=channel, approval_ref=approval, actor_ip=ip, api_key=key, user_agent=ua,
                         next_run=str(run_date) if run_date else "", days_to_run=days, score=score,
                         decision=decision, reasons=" | ".join(reasons), chain=chain, is_bank=bool(c["is_bank"]),
                         callback_note=safe_callback))

    decisions = pd.DataFrame(rows)
    return decisions, clocks


def metrics(decisions: pd.DataFrame, labels: pd.DataFrame | None):
    """Accuracy against TEST labels. Only bank-detail changes are scored."""
    if labels is None or not len(labels):
        return None
    d = decisions[decisions["is_bank"]].merge(labels[["change_id", "label", "scenario"]], on="change_id", how="left")
    d["label"] = d["label"].fillna("benign")
    fraud, benign = d[d["label"] == "fraud"], d[d["label"] != "fraud"]
    held_f, review_f = (fraud["decision"] == "HOLD").sum(), (fraud["decision"] == "REVIEW").sum()
    held_b, review_b = (benign["decision"] == "HOLD").sum(), (benign["decision"] == "REVIEW").sum()
    return dict(
        bank_changes=len(d), frauds=len(fraud), benign=len(benign),
        fraud_held=int(held_f), fraud_review=int(review_f), fraud_missed=int(len(fraud) - held_f - review_f),
        benign_held=int(held_b), benign_review=int(review_b), benign_allowed=int(len(benign) - held_b - review_b),
        detection_rate=round(100 * held_f / len(fraud), 1) if len(fraud) else None,
        flagged_rate=round(100 * (held_f + review_f) / len(fraud), 1) if len(fraud) else None,
        false_alarm_rate=round(100 * held_b / len(benign), 1) if len(benign) else None,
        table=d,
    )
