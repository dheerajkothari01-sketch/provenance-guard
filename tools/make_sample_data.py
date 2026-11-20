"""
Generate a TEST dataset in the CR-26-047 evidence formats (Appendix D columns).

THIS IS SYNTHETIC TEST DATA, NOT CASE EVIDENCE.
It plants known attacks and known-normal activity so the guard can be measured.
Ground truth lives in labels.csv (not part of the case format).

Usage:  python tools/make_sample_data.py [output_folder]
"""
import json
import random
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pandas as pd

random.seed(47)
OUT = Path(sys.argv[1] if len(sys.argv) > 1 else Path(__file__).resolve().parent.parent / "data" / "sample")
OUT.mkdir(parents=True, exist_ok=True)

UTC = timezone.utc
START = datetime(2026, 6, 3, tzinfo=UTC)
END = datetime(2026, 9, 7, 23, 59, tzinfo=UTC)
E18_START = datetime(2026, 9, 1, tzinfo=UTC)

# ---------------------------------------------------------------- reference
TB_KEY = "key_tb_7f3a"
BK_KEY = "key_bk_19d0"
RP_KEY = "key_rp_5521"
TB_UA = "TallyBridge-Sync/3.1"
FIN_USERS = ["farah.dsouza", "madhavi.sundar", "kiran.rao", "neha.pillai"]
OFFICE_IPS = [f"172.16.10.{i}" for i in range(20, 60)]
REMOTE_IPS = ["49.207.183.12", "106.51.77.140", "117.193.40.9"]

_haulier = ["Southern", "Coastal", "Deccan", "Kaveri", "Nilgiri", "Marina", "Vaigai", "Palar",
            "Ponni", "Tamira", "Eastern", "Ghats", "Malabar", "Chola", "Pandya", "Konkan"]
_kind = ["Haulage", "Logistics", "Fuels", "Packaging", "Carriers", "Transport", "Roadways", "Freight"]
VENDORS = {}
for i in range(80):
    vid = f"V{1001 + i}"
    VENDORS[vid] = f"{_haulier[i % len(_haulier)]} {_kind[i // len(_haulier)]} Pvt Ltd"


def acct():
    return "".join(random.choice("0123456789") for _ in range(14))


def ifsc():
    return random.choice(["HDFC", "ICIC", "SBIN", "UTIB", "KKBK"]) + "000" + "".join(random.choice("0123456789") for _ in range(4))


BANK = {v: {"bank_account": acct(), "ifsc": ifsc()} for v in VENDORS}
OTHER = {v: {"address": f"{random.randint(1, 200)}, Industrial Estate, Chennai",
             "contact_email": f"accounts@{v.lower()}.example",
             "phone": f"+91-44-{random.randint(20000000, 29999999)}",
             "payment_terms": random.choice(["NET15", "NET30", "NET45"])} for v in VENDORS}

e01_rows, e19_rows, e15_rows, labels, sso_rows = [], [], [], [], []
_ev = [700000]
DEVICE_FROM = datetime(2026, 6, 20, tzinfo=UTC)   # E03 device field is blank before 20 June (as in the case)
STAFF_DEVICE = {"farah.dsouza": "LAP-FIN-031", "madhavi.sundar": "LAP-FIN-007", "kiran.rao": "LAP-FIN-044",
                "neha.pillai": "LAP-FIN-052"}
OTHER_STAFF = [f"{n}.{s}" for n, s in [("arun", "k"), ("divya", "r"), ("suresh", "m"), ("lakshmi", "p"),
               ("vikram", "s"), ("meena", "t"), ("rahul", "v"), ("priya", "n"), ("sunita", "iyer"),
               ("aditi", "kapoor"), ("pradeep", "shah"), ("prakash", "menon"), ("karthik", "b"), ("anu", "j"),
               ("gopal", "d"), ("revathi", "s"), ("imran", "a"), ("shalini", "g"), ("manoj", "r"), ("deepa", "c")]]


def signin(t, user, ip, city, device, result="success", mfa="success", reason="", method="password+mfa"):
    _ev[0] += 1
    sso_rows.append(dict(ts_utc=t.strftime("%Y-%m-%dT%H:%M:%SZ"), event_id=f"sso-{_ev[0]}", user=user,
                         source_ip=ip, city=city, auth_method=method, mfa_result=mfa if result == "success" else "",
                         device_id=device if t >= DEVICE_FROM else "", result=result, failure_reason=reason))
_req = [100000]
_chg = [5000]
_flow = [900000]
_apr = [100]


def req_id():
    _req[0] += 1
    return f"req-{_req[0]}"


def chg_id():
    _chg[0] += 1
    return f"chg-{_chg[0]}"


def flow_id():
    _flow[0] += 1
    return f"fl-{_flow[0]}"


def apr():
    _apr[0] += 1
    return f"APR-2026-{_apr[0]:04d}"


def iso(t):
    return t.strftime("%Y-%m-%dT%H:%M:%SZ")


def api_call(t, key, ip, ua, endpoint, method, recs, status=200):
    rid = req_id()
    e01_rows.append(dict(ts_utc=iso(t), request_id=rid, api_key_id=key, caller_ip=ip, user_agent=ua,
                         endpoint=endpoint, method=method, records_returned=recs, status=status))
    return rid


def flow(t, src, label, out_b, in_b):
    e15_rows.append(dict(ts_utc=iso(t), flow_id=flow_id(), src_ip=src, src_label=label, dst_system="LedgerOne",
                         dst_port=443, bytes_out=out_b, bytes_in=in_b, tunnel_id="TB-TUN-01", result="allowed"))


def change(t, vendor, field, new, changed_by, channel, approval, source_ip, request_id="",
           label="benign", scenario="normal"):
    store = BANK[vendor] if field in BANK[vendor] else OTHER[vendor]
    old = store[field]
    store[field] = new
    cid = chg_id()
    e19_rows.append(dict(ts_utc=iso(t), change_id=cid, vendor_id=vendor, vendor_name=VENDORS[vendor],
                         field=field, old_value=old, new_value=new, changed_by=changed_by, channel=channel,
                         approval_ref=approval, source_ip=source_ip, request_id=request_id))
    labels.append(dict(change_id=cid, label=label, scenario=scenario))
    return cid


# ---------------------------------------------------------------- normal background
day = START
while day <= END:
    # nightly TallyBridge sync over the private link (~19:30-20:30 UTC = 01:00-02:00 IST)
    base = day.replace(hour=19, minute=30) + timedelta(minutes=random.randint(-20, 25))
    for k in range(random.randint(10, 16)):
        t = base + timedelta(seconds=40 * k)
        src = random.choice(["10.20.4.11", "10.20.4.12"])
        ep, m = random.choice([("/api/v2/vendors", "GET"), ("/api/v2/invoices", "GET"),
                               ("/api/v2/invoices", "POST"), ("/api/v2/payments/status", "GET")])
        api_call(t, TB_KEY, src, TB_UA, ep, m, random.randint(20, 900))
        flow(t, src, "tb-sync-0" + src[-1], random.randint(4000, 90000), random.randint(9000, 400000))
    # occasional contact sync written by TallyBridge (non-payment field, no approval needed)
    if random.random() < 0.18:
        v = random.choice(list(VENDORS))
        t = base + timedelta(minutes=12)
        rid = api_call(t, TB_KEY, "10.20.4.11", TB_UA, f"/api/v2/vendors/{v}", "PATCH", 1)
        flow(t, "10.20.4.11", "tb-sync-01", 2100, 800)
        change(t, v, "contact_email", f"billing{random.randint(1, 9)}@{v.lower()}.example",
               TB_KEY, "api", "", "10.20.4.11", rid, scenario="integration contact sync")
    # backup + reporting from the server network
    api_call(day.replace(hour=21, minute=5), BK_KEY, "172.16.5.20", "LedgerBackup/2.4", "/api/v2/export", "GET",
             random.randint(30000, 36000))
    api_call(day.replace(hour=22, minute=40), RP_KEY, "172.16.5.31", "ReportRunner/1.9", "/api/v2/reports", "GET",
             random.randint(200, 1500))

    # finance staff changes on weekdays (IST working hours = 03:00-13:30 UTC)
    if day.weekday() < 5:
        for u, dev in STAFF_DEVICE.items():
            remote = random.random() < 0.12
            ip0 = random.choice(REMOTE_IPS) if remote else random.choice(OFFICE_IPS)
            t0 = day.replace(hour=3, minute=random.randint(0, 40))
            if random.random() < 0.06:  # a harmless password typo
                signin(t0 - timedelta(minutes=1), u, ip0, "Chennai", dev, "failure", reason="wrong password")
            signin(t0, u, ip0, "Chennai", dev)
        for u in random.sample(OTHER_STAFF, 14):
            signin(day.replace(hour=3, minute=random.randint(0, 59)), u, random.choice(OFFICE_IPS), "Chennai",
                   "LAP-" + u.split(".")[0].upper()[:4] + "-01")
        # network contractor on the road (normal, touches no finance data)
        signin(day.replace(hour=4, minute=10), "colin.lawson", f"103.21.{random.randint(10, 250)}.{random.randint(2, 250)}",
               random.choice(["Chennai", "Bengaluru", "Hyderabad", "Mumbai", "Coimbatore"]), "LAP-CTR-002")
        # ex-employee's kiosk login that was never disabled (no vendor changes)
        if day > datetime(2026, 6, 30, tzinfo=UTC) and random.random() < 0.3:
            signin(day.replace(hour=2, minute=45), "rohan.menon", "172.16.30.12", "Chennai", "KIOSK-WH-02",
                   method="password")
        for _ in range(random.randint(4, 7)):
            t = day.replace(hour=random.randint(4, 12), minute=random.randint(0, 59))
            v = random.choice(list(VENDORS))
            user = random.choice(FIN_USERS)
            ip = random.choice(OFFICE_IPS) if random.random() < 0.85 else random.choice(REMOTE_IPS)
            if random.random() < 0.22:  # legitimate bank-detail update, always approved
                f = random.choice(["bank_account", "ifsc"])
                change(t, v, f, acct() if f == "bank_account" else ifsc(), user, "ui", apr(), ip,
                       scenario="approved bank update")
            else:
                f = random.choice(["address", "contact_email", "phone", "payment_terms"])
                newv = {"address": f"{random.randint(1, 200)}, SIDCO Estate, Chennai",
                        "contact_email": f"finance@{v.lower()}.example",
                        "phone": f"+91-44-{random.randint(20000000, 29999999)}",
                        "payment_terms": random.choice(["NET15", "NET30", "NET45"])}[f]
                change(t, v, f, newv, user, "ui", random.choice(["", "", apr()]), ip, scenario="routine edit")
    day += timedelta(days=1)

# month-end bulk clean-ups (approved, one reference per run)
for d, ref in [(datetime(2026, 6, 30, 9, 0, tzinfo=UTC), "APR-2026-MEC-06"),
               (datetime(2026, 7, 31, 9, 0, tzinfo=UTC), "APR-2026-MEC-07"),
               (datetime(2026, 8, 31, 9, 0, tzinfo=UTC), "APR-2026-MEC-08")]:
    vs = random.sample(list(VENDORS), 24)
    for i, v in enumerate(vs):
        t = d + timedelta(seconds=25 * i)
        if i < 3:
            f = "bank_account"
            nv = acct()
        else:
            f = random.choice(["address", "payment_terms", "contact_email"])
            nv = {"address": f"{random.randint(1, 200)}, Guindy, Chennai",
                  "payment_terms": random.choice(["NET30", "NET45"]),
                  "contact_email": f"ap@{v.lower()}.example"}[f]
        change(t, v, f, nv, "farah.dsouza", "bulk", ref, "172.16.10.41", scenario="month-end clean-up")

# benign but unapproved bank edits by finance staff, far from a run (should be REVIEW, not HOLD)
change(datetime(2026, 6, 15, 6, 20, tzinfo=UTC), "V1009", "ifsc", ifsc(), "kiran.rao", "ui", "", "172.16.10.33",
       scenario="unapproved staff edit (policy slip)")
change(datetime(2026, 7, 14, 7, 5, tzinfo=UTC), "V1053", "bank_account", acct(), "neha.pillai", "ui", "",
       "49.207.183.12", scenario="unapproved staff edit, remote (policy slip)")

# ---------------------------------------------------------------- planted attacks
MULE = "50100478821936"


def attack(t, v, field, new, ip, ua, scenario, approval="", via_link=False, key=TB_KEY):
    rid = api_call(t, key, ip, ua, f"/api/v2/vendors/{v}", "PATCH", 1)
    if via_link:
        flow(t, ip, "tb-batch-03", 2300, 900)
    change(t, v, field, new, key, "api", approval, ip, rid, label="fraud", scenario=scenario)


# reconnaissance before the change: bulk vendor + payment pulls from outside the private link
for t, ip in [(datetime(2026, 8, 19, 22, 10, tzinfo=UTC), "45.137.21.9"),
              (datetime(2026, 9, 4, 21, 30, tzinfo=UTC), "185.220.101.47")]:
    api_call(t, TB_KEY, ip, "TallyBridge-Sync/3.2", "/api/v2/vendors", "GET", 300)
    api_call(t + timedelta(minutes=2), TB_KEY, ip, "TallyBridge-Sync/3.2", "/api/v2/payments/schedule", "GET", 46)

attack(datetime(2026, 8, 21, 22, 5, tzinfo=UTC), "V1044", "bank_account", "62310055667788", "45.137.21.9",
       "TallyBridge-Sync/3.2", "attack: before 23 Aug run")
attack(datetime(2026, 9, 5, 21, 47, tzinfo=UTC), "V1012", "bank_account", MULE, "185.220.101.47",
       "TallyBridge-Sync/3.2", "attack: before 8 Sep run")
attack(datetime(2026, 9, 5, 21, 48, tzinfo=UTC), "V1012", "ifsc", "HDFC0009912", "185.220.101.47",
       "TallyBridge-Sync/3.2", "attack: before 8 Sep run")
attack(datetime(2026, 9, 5, 21, 52, tzinfo=UTC), "V1037", "bank_account", MULE, "185.220.101.47",
       "TallyBridge-Sync/3.2", "attack: mule account reused")
attack(datetime(2026, 9, 6, 2, 10, tzinfo=UTC), "V1058", "bank_account", "62310055667788", "45.137.21.9",
       "TallyBridge-Sync/3.2", "attack: before 8 Sep run")

# variations (test that the guard does not depend on known attacker IPs)
attack(datetime(2026, 9, 6, 20, 15, tzinfo=UTC), "V1066", "bank_account", "91827364550012", "10.20.4.13",
       TB_UA, "variation: from inside the private link, normal client", via_link=True)
attack(datetime(2026, 8, 31, 9, 6, tzinfo=UTC), "V1071", "bank_account", "77001234558899", "103.86.44.21",
       TB_UA, "variation: hidden in month-end clean-up, unknown IP")
attack(datetime(2026, 7, 14, 21, 0, tzinfo=UTC), "V1025", "bank_account", "33445566778899", "10.20.4.11",
       TB_UA, "variation: forged approval ref, inside link (known miss)", approval="APR-2026-0412", via_link=True)

# ---------------------------------------------------------------- new attacks (v2)
# A. stolen staff login: brute-forced password, new device + city, unapproved bank change 2 days before a run
t = datetime(2026, 8, 20, 22, 40, tzinfo=UTC)
for i in range(4):
    signin(t - timedelta(minutes=8 - 2 * i), "kiran.rao", "77.83.246.15", "Amsterdam", "WIN-UNKNOWN-7F", "failure",
           reason="wrong password")
signin(t, "kiran.rao", "77.83.246.15", "Amsterdam", "WIN-UNKNOWN-7F")
change(t + timedelta(minutes=15), "V1019", "bank_account", "40220099887766", "kiran.rao", "ui", "", "77.83.246.15",
       label="fraud", scenario="attack: stolen staff login, unapproved")
# B. stolen staff login + forged approval number, far from a run (expected: REVIEW, not HOLD)
t = datetime(2026, 7, 30, 21, 10, tzinfo=UTC)
signin(t, "neha.pillai", "91.240.118.30", "Frankfurt", "MAC-UNKNOWN-22", mfa="bypassed")
change(t + timedelta(minutes=10), "V1031", "bank_account", "40220011223344", "neha.pillai", "ui", "APR-2026-0915",
       "91.240.118.30", label="fraud", scenario="attack: stolen staff login + forged approval")
# C. business-email compromise: fraudster gets the phone changed, then a deceived, APPROVED bank change
change(datetime(2026, 8, 27, 6, 0, tzinfo=UTC), "V1048", "phone", "+91-90000-71234", "kiran.rao", "ui", "",
       "172.16.10.27", label="fraud", scenario="BEC: phone changed first")
signin(datetime(2026, 9, 5, 5, 50, tzinfo=UTC), "farah.dsouza", "172.16.10.41", "Chennai", "LAP-FIN-031")
change(datetime(2026, 9, 5, 6, 10, tzinfo=UTC), "V1048", "bank_account", "40220055667788", "farah.dsouza", "ui",
       "APR-2026-0961", "172.16.10.41", label="fraud", scenario="BEC: approved bank change after phone change")
# D. retired (disabled) payroll key used from inside the server network, 1 day before a run
attack(datetime(2026, 8, 6, 20, 0, tzinfo=UTC), "V1077", "bank_account", "40220077001122", "172.16.5.44",
       "python-requests/2.32", "attack: disabled key from inside", key="key_pe_0091")
# E. read-only reporting key suddenly writes bank details, from its normal host
attack(datetime(2026, 9, 2, 20, 30, tzinfo=UTC), "V1062", "bank_account", "40220033445566", "172.16.5.31",
       "ReportRunner/1.9", "attack: read-only key writes bank details", key=RP_KEY)
# F. slow attack: one change, 10 days before a run, from a cloud IP not on any list
attack(datetime(2026, 6, 13, 20, 50, tzinfo=UTC), "V1003", "bank_account", "40220088990011", "52.66.140.201",
       TB_UA, "attack: far from a run, unknown cloud IP")

# tricky but legitimate events (must not be held)
t = datetime(2026, 8, 10, 3, 50, tzinfo=UTC)         # new laptop issued, then an approved change
signin(t, "farah.dsouza", "172.16.10.41", "Chennai", "LAP-FIN-031-NEW")
change(t + timedelta(hours=2), "V1014", "bank_account", acct(), "farah.dsouza", "ui", apr(), "172.16.10.41",
       scenario="tricky normal: new laptop, approved")
t = datetime(2026, 8, 12, 4, 0, tzinfo=UTC)          # manager travelling, approved change from a hotel
signin(t, "madhavi.sundar", "106.200.14.9", "Bengaluru", "LAP-FIN-007")
change(t + timedelta(minutes=30), "V1027", "ifsc", ifsc(), "madhavi.sundar", "ui", apr(), "106.200.14.9",
       scenario="tricky normal: manager travelling, approved")
t = datetime(2026, 7, 21, 3, 30, tzinfo=UTC)          # two password typos, then an approved change
signin(t - timedelta(minutes=2), "kiran.rao", "172.16.10.27", "Chennai", "LAP-FIN-044", "failure", reason="wrong password")
signin(t - timedelta(minutes=1), "kiran.rao", "172.16.10.27", "Chennai", "LAP-FIN-044", "failure", reason="wrong password")
signin(t, "kiran.rao", "172.16.10.27", "Chennai", "LAP-FIN-044")
change(t + timedelta(hours=1), "V1033", "bank_account", acct(), "kiran.rao", "ui", apr(), "172.16.10.27",
       scenario="tricky normal: password typos, approved")
change(datetime(2026, 9, 8, 4, 30, tzinfo=UTC) - timedelta(days=31), "V1040", "phone", "+91-44-24561234",
       "neha.pillai", "ui", apr(), "172.16.10.52", scenario="routine edit")
change(datetime(2026, 9, 7, 5, 30, tzinfo=UTC), "V1040", "bank_account", acct(), "neha.pillai", "ui", apr(),
       "172.16.10.52", scenario="tricky normal: phone changed a month earlier, approved")
change(datetime(2026, 7, 8, 4, 0, tzinfo=UTC), "V1055", "bank_account", acct(), "madhavi.sundar", "ui", apr(),
       "172.16.10.21", scenario="tricky normal: urgent approved change on payment day")

# ---------------------------------------------------------------- write files
e01 = pd.DataFrame(e01_rows).sort_values("ts_utc")
ts = pd.to_datetime(e01["ts_utc"], utc=True)
e01[ts < E18_START].to_csv(OUT / "E01_ledgerone_api_log.csv", index=False)
e01[ts >= E18_START].to_csv(OUT / "E18_ledgerone_api_log_continued.csv", index=False)
pd.DataFrame(e19_rows).sort_values("ts_utc").to_csv(OUT / "E19_vendor_change_log.csv", index=False)
pd.DataFrame(e15_rows).sort_values("ts_utc").to_csv(OUT / "E15_private_link_flows.csv", index=False)
pd.DataFrame(labels).to_csv(OUT / "labels_TEST_ONLY.csv", index=False)

e17 = [
    dict(indicator="185.220.101.47", type="ip", first_seen="2026-08-19", last_seen="2026-09-06", confidence="high",
         vendor_note="Seen using customer integration credentials"),
    dict(indicator="45.137.21.9", type="ip", first_seen="2026-08-18", last_seen="2026-09-06", confidence="medium",
         vendor_note="Associated hosting range"),
    dict(indicator="TallyBridge-Sync/3.2", type="user_agent", first_seen="2026-08-18", last_seen="2026-09-06",
         confidence="medium", vendor_note="Not a released client version"),
    dict(indicator="91.219.236.18", type="ip", first_seen="2026-08-25", last_seen="2026-08-27", confidence="low",
         vendor_note="Scanning only"),
    dict(indicator="tallybridge-support.net", type="domain", first_seen="2026-08-20", last_seen="2026-08-28",
         confidence="low", vendor_note="Look-alike domain"),
]
pd.DataFrame(e17).to_csv(OUT / "E17_indicator_list.csv", index=False)
pd.DataFrame(sso_rows).sort_values("ts_utc").to_csv(OUT / "E03_sso_log.csv", index=False)

e04 = [
    dict(integration="TallyBridge Connect (LedgerOne)", credential_id=TB_KEY, system="LedgerOne",
         vendor="TallyBridge Software Pvt Ltd", scope="invoices:read,invoices:write,vendors:read,vendors:write",
         owner="Finance IT", created="2024-06-12", last_review="2024-06-12", ip_restriction="",
         token_lifetime_days=3650, last_used="2026-09-06", status="active"),
    dict(integration="TallyBridge Connect (HelpDeskr)", credential_id="key_tb_hd_22c1", system="HelpDeskr",
         vendor="TallyBridge Software Pvt Ltd", scope="tickets:read,exports:create", owner="Support Ops",
         created="2024-06-12", last_review="2024-06-12", ip_restriction="", token_lifetime_days=3650,
         last_used="2026-09-06", status="active"),
    dict(integration="Nightly backup agent", credential_id=BK_KEY, system="LedgerOne", vendor="internal",
         scope="read:*", owner="IT", created="2023-02-01", last_review="2026-01-15", ip_restriction="172.16.5.0/24",
         token_lifetime_days=365, last_used="2026-09-07", status="active"),
    dict(integration="Reporting tool", credential_id=RP_KEY, system="LedgerOne", vendor="internal",
         scope="reports:read", owner="Operations IT", created="2023-05-10", last_review="2026-02-02",
         ip_restriction="172.16.5.0/24", token_lifetime_days=365, last_used="2026-09-07", status="active"),
    dict(integration="Customer document portal", credential_id="key_cp_a10e", system="BlueVault",
         vendor="internal", scope="docs:read", owner="Support Ops", created="2025-02-03", last_review="2025-02-03",
         ip_restriction="", token_lifetime_days=730, last_used="2026-09-07", status="active"),
    dict(integration="Helpdesk weekly reporting", credential_id="key_hr_77b2", system="HelpDeskr",
         vendor="internal", scope="tickets:read", owner="Support Ops", created="2024-01-09", last_review="2025-01-10",
         ip_restriction="172.16.0.0/16", token_lifetime_days=365, last_used="2026-09-01", status="active"),
    dict(integration="Payroll export (retired)", credential_id="key_pe_0091", system="LedgerOne", vendor="internal",
         scope="payroll:read", owner="Finance IT", created="2022-08-01", last_review="2024-08-01",
         ip_restriction="172.16.5.0/24", token_lifetime_days=365, last_used="2025-03-30", status="disabled"),
    dict(integration="Ops dashboard", credential_id="key_od_3be4", system="LedgerOne", vendor="internal",
         scope="shipments:read", owner="Operations IT", created="2024-11-20", last_review="2025-11-21",
         ip_restriction="172.16.0.0/16", token_lifetime_days=365, last_used="2026-09-07", status="active"),
]
(OUT / "E04_connected_software_register.json").write_text(json.dumps(e04, indent=2))

lab = pd.DataFrame(labels)
print(f"written to {OUT}")
print(f"E01 rows {int((ts < E18_START).sum())}, E18 rows {int((ts >= E18_START).sum())}, "
      f"E19 rows {len(e19_rows)}, E15 rows {len(e15_rows)}")
print(lab.groupby(['label', 'scenario']).size().to_string())
