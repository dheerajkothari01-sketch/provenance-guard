# Payment-Run Provenance Guard

**CRIMEATHON'26 · Case CR-26-047 · Defense track · Team Brute Force**
Dheeraj · Ashwantika · Mahashri · Jazib

> *Trust the chain, not the pattern.* Before any money moves, check where every vendor bank-detail change came
> from, and hold the payment until two different people confirm it.

At Harbor & Finch, a trusted third-party integration key (TallyBridge) could rewrite a vendor's bank details with no
approval and no second check, days before a payment run. Nothing checked *where* a change came from. This tool does.

For every bank-detail change in the vendor change log (E19), it rebuilds the change's **provenance chain** across
systems, scores how well the chain holds up, and decides **ALLOW**, **REVIEW** or **HOLD**. Held changes go to a
two-person approval queue with a full audit trail.

```
E19 change ─request_id─► E18/E01 API call ─api_key_id─► E04 credential (scope, status, review age)
     │                          │
     │              caller_ip ──┼──► expected network (E04 restriction + private link + learned history)
     │                          ├──► E15 private-link flow at that time (corroboration)
     │                          └──► E17 outside-company indicators
     ├─ staff change ──────────────► E03 sign-in before the change (new device / city, MFA, failed attempts)
     ├─ same vendor ───────────────► phone number changed shortly before? → safe call-back number
     └─ change time ───────────────► payment calendar (8th / 23rd, India time)
```

The detection engine (`engine/guard.py`) has no UI dependency, so it runs on any folder of files in the case
formats, including data it has never seen.

---

## Quick start

Requires **Python 3.10+**. On Windows, tick **"Add python.exe to PATH"** when installing.

```bash
git clone <this-repository-url>
cd provenance-guard
pip install -r requirements.txt      # pandas, streamlit, plotly

streamlit run app.py                 # dashboard: opens http://localhost:8501
```

Windows shortcut: double-click `RUN_ME_windows.bat`. Mac/Linux: `./run_mac_linux.sh`.

If `python` isn't recognised on Windows, use `py` instead (`py -m pip install -r requirements.txt`,
`py -m streamlit run app.py`).

### Command line (no dashboard)

```bash
python run_guard.py data/sample --out output            # test data
python run_guard.py path/to/evidence --out output       # supplied evidence
```

Writes `output/decisions.csv` (every change, score, decision, reasons) and `output/report.md`.
Options: `--hold 60 --review 30 --window 3`.

### Sign-in (starting accounts, for the evaluation panel)

The sign-in page shows no usernames or passwords. These four starting accounts are listed here for the judges only:

| Username | Password | Role | Can do |
| --- | --- | --- | --- |
| `farah` | `Farah@2026` | Senior Accountant | Record the call-back (vendor phoned on the number on file); clear or escalate reviews |
| `madhavi` | `Madhavi@2026` | Finance Manager | Release after a confirmed call-back, or block; clear or escalate reviews |
| `aditi` | `Aditi@2026` | IT Security Administrator | Owns the detection rules; **creates, disables and resets staff accounts**; block or escalate; **never release** |
| `auditor` | `Audit@2026` | Audit Committee | Read-only |

Passwords are salted PBKDF2-SHA256 hashes in `config/users.json`. Change them with `python tools/make_users.py`.
**Staff accounts:** there is no self-sign-up. IT Security creates each account in the **👥 Staff accounts** tab with a
temporary password (10+ characters, upper/lower case, number, symbol). The person must set their own password at first
sign-in. Disabled accounts can't sign in. Every create, disable, reset and refused attempt goes to the audit trail.
Accounts created this way are stored in `state/accounts.json`.

**🧭 Guide button (top right):** a guided tour for the signed-in role. It clicks through the tabs that matter to that
person and explains each one. Each of the four roles gets its own tour.

Vendors deliberately have **no** account: they are outside the company, and outside access is how this attack
happened. Vendors are only ever contacted by call-back on the number already on file.

To start the demo fresh, sign in as `madhavi` and press **Reset demo queue**, or delete the `state/` folder.

---

## Put it online (Streamlit Community Cloud, free)

1. Push this folder to a GitHub repository (`app.py` and `requirements.txt` at the top level).
2. Go to **share.streamlit.io**, sign in with GitHub, click **Create app**, then **Deploy a public app from GitHub**.
3. Repository `<you>/provenance-guard`, branch `main`, main file `app.py`. Under **Advanced settings**, choose Python 3.12.
4. Click **Deploy**. Every later `git push` updates the live site automatically.

Note: on the free tier, approvals, created accounts and the audit log reset when the app restarts.

## Input files

Files are recognised by **name prefix**. Only **E19** is required; each extra file adds a link to the chain.

| File | Format | Columns used |
| --- | --- | --- |
| **E19** vendor record change log | CSV | ts_utc, change_id, vendor_id, vendor_name, field, old_value, new_value, changed_by, channel, approval_ref, source_ip, request_id |
| E18 + E01 LedgerOne API logs | CSV | ts_utc, request_id, api_key_id, caller_ip, user_agent, endpoint, method |
| E04 connected software register | JSON | credential_id, integration, scope, ip_restriction, last_review, status |
| E03 single sign-on log | CSV | ts_utc, user, source_ip, city, mfa_result, device_id, result |
| E15 private-link flow log | CSV | ts_utc, src_ip, src_label |
| E17 indicator list | CSV | indicator, type, confidence |

**Clocks:** every timestamp is converted to UTC before anything is joined. E02 (tenant local time) is assumed to be
IST (−330 minutes); E05's unsynchronised clock offset is set in the dashboard (⚙️ Rules tab). Payment-run dates use India
time.

---

## How a change is scored

Only bank-detail changes are scored (bank account, IFSC, IBAN, SWIFT, beneficiary, payee).

| Rule | Points |
| --- | --- |
| No approval reference on a bank-detail change | 40 |
| Key is not allowed to change vendor records, or is disabled (E04) | 30 |
| Matches an outside-company indicator (E17) | 30 |
| Request came from outside the key's expected network | 25 |
| Staff sign-in before the change looked risky (E03: new device or city, MFA failed/bypassed, 3+ failed attempts) | 25 |
| Key has little or no history of *approved* bank changes | 20 |
| Same new account given to more than one vendor (mule) | 20 |
| Vendor's phone number changed in the 14 days before the bank change | 20 |
| Within 3 days before a payment run | 15 |
| Within 7 days before a payment run | 5 |
| Changed by software (API key), not a person | 10 |
| Staff change made from outside the office network | 10 |
| API call for the change missing from the log | 10 |

Capped at 100. **HOLD ≥ 60 · REVIEW ≥ 30 · ALLOW < 30.** The largest single rule is 40, so **at least two
independent signals must agree** before money is held. All weights, thresholds and windows are editable by IT
Security in the dashboard.

- **Expected network** = the key's E04 IP restriction + the configured private link (10.20.4.0/24) + any /24 that
  carried at least 5% of the key's earlier traffic. Nothing depends on knowing the attacker's IP.
- **History** counts only earlier *approved* bank changes, so an attacker's own changes can't make a key look normal.
- **Safe call-back number:** if the vendor's phone changed recently, the app shows the number from *before* the change.

## Approval workflow (two-person rule)

1. **HOLD** → the Senior Accountant calls the vendor on the number already on file, never one supplied with the
   change, and records *confirmed* or *not confirmed*.
2. **Confirmed** → the Finance Manager releases it. **Not confirmed** → blocked.
3. **REVIEW** → cleared, or escalated into the HOLD path.

Enforced in `engine/workflow.py`, not only in the interface:

- each action is limited to its roles
- nobody can act on a change they made
- whoever recorded the call-back can't release it
- nothing is released without a confirmed call-back

Every sign-in, action, rule change, export and **refused attempt** is written to `state/audit_log.jsonl` and shown
in the 🧾 Audit tab.

## Dashboard

| Tab | Shows |
| --- | --- |
| 🏠 Start here | Plain-English headline (payments stopped before the next run), how it works in 3 steps, top stopped payments, each role's next step |
| 📊 Overview | Totals and a timeline of risk scores against payment-run dates |
| 🔎 Investigate | One change traced link by link, green or red, with the score breakdown |
| 📋 All changes | Every bank change with score, decision, queue status and reasons |
| 👥 Staff accounts | IT Security only: create, disable and reset staff accounts |
| ✋ Approvals | Call-back, release, block, clear, escalate (role-gated) with the safe call-back number |
| 🧪 Try it live | Make up a bank-detail change (or pick a scenario) and see it scored instantly, without touching the real data |
| 🎯 Accuracy | Detection and false-alarm rates (labelled test data only) |
| ⚙️ Rules | Thresholds, windows, networks, rule weights, clock offsets (IT Security only) |
| 🗂️ Data | Files loaded, row counts, and each file's clock conversion to UTC |
| 🧾 Audit | Exports (decisions.csv, report.md, hold_queue.csv) and every action and refused attempt |

---

## Results on the test dataset

`data/sample` is **synthetic test data** in the case's exact formats (`tools/make_sample_data.py`, seed 47). It is
**not** the case evidence. Ground truth: `labels_TEST_ONLY.csv`.

It holds 484 vendor changes (114 bank-detail changes), 1,472 API calls, 1,349 sign-ins and 1,265 private-link flows.
Most activity is normal, as in real life: 100 normal bank changes,
with 14 planted attacks:

- stolen integration key from attacker IPs
- mule accounts
- an attack from *inside* the private link
- an attack hidden in a month-end clean-up from an unknown IP
- a forged approval
- a disabled key used from inside the network
- a read-only key writing bank details
- a slow attack 10 days before a run
- a stolen staff login, with and without a forged approval
- a phone-then-bank email scam

There are also tricky normal events designed to cause false alarms: a new laptop, password typos, a travelling
manager, an urgent payment-day change, and a phone changed a month earlier.

| Measure | Result |
| --- | --- |
| Attacks held | **11 / 14** (78.6%) |
| Attacks held or sent to review | **14 / 14** (100%) |
| Normal bank changes held (false alarms) | **1 / 100** (an unapproved staff edit right after the vendor's phone changed) |
| Normal bank changes sent to review | 6 / 100 (an unapproved remote edit, a travelling manager, approved changes soon after a phone change) |

Full per-change results, errors and limitations: **[PROOF_PACK.md](PROOF_PACK.md)**
(rebuild with `python tools/build_proof_pack.py`).

## Known limitations

- Approval references aren't verified against an approval register (none supplied), so a forged reference lowers the
  score. Those cases reach REVIEW, not HOLD.
- A deceived manager approving a scam change (business-email compromise) reaches REVIEW; the protection is the
  call-back to the pre-change phone number.
- Learned networks can be poisoned by sustained traffic (>5% of a key's calls) from a new range.
- Weights are expert-set, not statistically fitted; with few labelled cases, rates carry wide uncertainty.
- Demo-grade sign-in (no lockout; append-only but not tamper-proof audit log). Production: company SSO with MFA,
  database, HTTPS, tamper-evident logs, direct integration with the payment run.

## Project structure

| Path | What |
| --- | --- |
| `engine/guard.py` | Detection engine: load, clocks, provenance chain, rules, decisions, accuracy |
| `engine/workflow.py` | Hold queue, two-person rule, audit trail |
| `engine/auth.py` | Accounts, password hashing, roles |
| `engine/report.py` | Markdown run report |
| `app.py` | Streamlit dashboard (sign-in + 10 tabs, incl. 🧪 Try it live) |
| `run_guard.py` | Command-line runner |
| `tools/make_sample_data.py` | Test-data generator |
| `tools/build_proof_pack.py` | Rebuilds PROOF_PACK.md from a live run |
| `tools/make_users.py` | Demo accounts |
| `data/sample/` | Generated test data (E01, E03, E04, E15, E17, E18, E19 + labels) |
| `docs/` | Screenshots, technical report, one-page summary |

Tech: Python 3, pandas, Streamlit, Plotly. Everything runs locally; no data leaves the machine.
