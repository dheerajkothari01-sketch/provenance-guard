# CR-26-047 Final Technical Report

CRIMEATHON'26 · Defense track · Team Brute Force: Dheeraj, Ashwantika, Mahashri, Jazib · 20 Nov 2026

## 1. Summary

**Conclusion:** the evidence points to a compromised third-party integration. TallyBridge Connect's long-lived, unrestricted API key was used to read finance data, bulk-export support tickets, and change vendor bank details in LedgerOne with no approval reference, in the days before the 8 September payment run. The attack succeeded because of three control gaps: an over-privileged integration key that was never reviewed, vendor bank changes that need no enforced approval or second check, and warnings that reached different people and were never joined up. We chose to defend the gap that loses money: **any trusted key or login can redirect a vendor payment unchecked.** Our Payment-Run Provenance Guard traces every bank-detail change across systems and holds the payment behind a two-person call-back when its trail doesn't hold up.

**On the data:** the official evidence package (the E01–E20 log files) was not available to our team; we worked from the case file and its description of each item. The timeline below is built from the case file's own statements. Where a fact needs the logs to confirm, we say what would confirm it. Our tool's measured results are on a synthetic dataset built in the exact evidence formats, and are labelled as such.

## 2. Reconstructed timeline

Dates come from the case file (Sections 1, 5, Appendix A and the evidence register). The last column says which evidence confirms or would confirm each step.

| Date | Event | Evidence |
| --- | --- | --- |
| 5–12 Jun 2024 | TallyBridge reviewed on self-reported answers, contract signed, access keys issued | E07, E08, E04 |
| Sep 2025 | Internal audit report issued; CISO leaves the same month; findings not confirmed closed | E11, E09 |
| 3 Jun 2026 | Earliest LedgerOne API log still held (90-day retention): anything earlier is lost | E01 |
| 30 Jun 2026 | Accounts payable clerk Rohan Menon leaves; his kiosk login stays active | E14, E03 |
| Jun–Aug 2026 | Likely use of TallyBridge's key: finance files read, tickets bulk-exported. *Confirm with E02 export jobs and E05 access by the integration principal* | E02, E05, E01 |
| 13 Aug 2026 | Warehouse reports the ex-employee's login still works | E03 |
| 21 Aug 2026 | Outside company sends a vague "precaution" notice to the accounts mailbox; IT never sees it | E12 |
| 23 Aug 2026 | Vendor payment run. *Check E19 for unapproved bank changes in the days before* | E19 |
| 24 Aug 2026 | Finance flags a HelpDeskr bill for unusual export jobs | E06, E02 |
| 28 Aug 2026 | Follow-up notice with an indicator list (IPs, client versions) | E16, E17 |
| 1 Sep 2026 | Audit Committee chair asks whether last year's findings were closed; no clear answer | E11 |
| 1–7 Sep 2026 | Highest-risk window. *Confirm: E19 bank changes with blank approval_ref, joined to E18 by request_id, caller IP checked against E17 and E15* | E19, E18, E17, E15 |
| 7 Sep 2026 | Investigation commissioned; logs end | Section 1 |
| 8 Sep 2026 | Next payment run: any redirected vendor would be paid to the attacker | Appendix B |

**Clock handling:** all times were normalised to UTC before linking. E02 is in the tenant's local time (assumed IST, −330 minutes). E05's unsynchronised clock needs an offset measured from one event seen in both E05 and another log.

## 3. Assumptions

1. **LedgerOne's server-side logs (E01, E18, E19) are genuine.** The attacker used an API key, not administrator access to logging.
2. **`request_id` in E19 reliably links a change to its API call in E18** (the case file states the link exists).
3. **E17 indicators and E15 host labels are unverified.** They come from the party that was breached, so we use them as one signal among several, never alone.
4. **E02 is in IST.** The case says "tenant's local time" without naming it; Harbor & Finch operates in Chennai.
5. **Usernames match across systems** (E19 `changed_by` and E03 `user`). The case warns names can differ, so a mapping table may be needed on real data.
6. **Payment runs fall on the 8th and 23rd in India time**, and money leaves on the run date (Appendix B).
7. **A bank change without an approval reference breaks policy,** because the process says Finance "is supposed to note an approval reference" (Appendix B, E10).

## 4. Alternative explanations

| Explanation | Verdict | Why | Evidence |
| --- | --- | --- | --- |
| Insider: ex-employee Rohan Menon | Set aside | His login stayed active (a real offboarding failure), but nothing ties it to vendor changes | E03, E14, E19 |
| Routine month-end clean-up | Set aside | Real clean-ups carry an approval reference; the suspicious changes don't | E19, Section 4 |
| Contractor Colin Lawson's multi-city logins | Set aside | Matches known travel; no finance access | E03 |
| Weekly Tuesday export, nightly backup and sync | Set aside as ordinary | Listed as normal in Section 4; the extra exports billed in August are the anomaly | E02, E06 |
| Rogue employee *at* TallyBridge rather than an outside attacker | **Open** | Their notices suggest outside misuse of their access, but the notices are self-serving. E20's address registrations would show who owns the attacker IPs | E12, E16, E17, E20 |
| TallyBridge's notice was false or spoofed | Not supported | Two notices a week apart with consistent indicators; sender domain checkable in E20 | E12, E16, E20 |
| Obvious fix: block the E17 IPs and rotate the key | Rejected as a full answer | Stops only this attacker. An attack from inside the private link, or from a new IP, gets through | E04, E15, E17 |

**What would change our conclusion:** every E19 bank change carrying a valid approval reference, or the E18 caller IPs sitting inside TallyBridge's private link (10.20.4.0/24) with none on the E17 list. That would point to an insider at Harbor & Finch or at TallyBridge rather than a stolen key.

## 5. Our solution and results

**Payment-Run Provenance Guard** (Python + pandas engine, Streamlit dashboard). For each bank-detail change in E19, it rebuilds the trail: the API call (E18/E01, joined by `request_id`), the key's permissions and status (E04), the network it came from (E04 restriction, private link, the key's own history), private-link traffic (E15), the attacker list (E17), the staff member's sign-in before the change (E03), whether the vendor's phone changed shortly before, and the payment calendar. Thirteen rules add up to a score: **HOLD at 60, REVIEW at 30**. No single rule exceeds 40, so at least two independent signals must agree before money is held.

Held changes go to a **two-person approval**: an accountant calls the vendor on the pre-change number on file, then a *different* person, the Finance Manager, releases or blocks it. Roles, the two-person rule and a full audit trail are enforced in the engine, not just the interface.

**Results on our synthetic test dataset** (484 vendor changes, 114 of them bank-detail changes; 14 planted attacks among 100 normal bank changes; tricky normal events designed to provoke false alarms):

| Measure | Result |
| --- | --- |
| Attacks held | 11 / 14 (78.6%) |
| Attacks held or sent to review | 14 / 14 (100%) |
| Normal bank changes held (false alarms) | 1 / 100 |
| Normal bank changes sent to review | 6 / 100 |

The three attacks sent to review instead of held all *look* approved: a forged approval from inside the private link (30), a stolen staff login with a forged approval (35), and a phone-then-bank scam approved by a deceived manager (35). For the scam, the app shows the vendor's phone number from *before* the change, so the call-back reaches the real vendor. Full per-change results are in the proof pack. The one normal change held was a staff bank edit with no approval reference, made soon after the vendor's phone number changed: the exact pattern of the scam, so a call-back is the right response, not a mistake to hide.

**Limits:** approval references aren't verified against a register; learned networks can be poisoned by sustained traffic; the weights are expert-set; and these rates come from our own test data, with few cases, so they carry wide uncertainty.

## 6. Conclusions and recommendations

The right question was not "who attacked us?" but **"why could a trusted key move money unchecked?"** The breach at TallyBridge was the trigger; Harbor & Finch's own controls let it turn into payment fraud.

**Do now (before the next payment run):**

1. Stop payment to any vendor whose bank details changed since 1 September without an approval reference, until confirmed by call-back to the pre-change number on file.
2. Remove `vendors:write` from TallyBridge's key, lock it to 10.20.4.0/24, rotate it, and shorten its lifetime.
3. Disable leavers' accounts (Rohan Menon) and reconcile the HR and IT staff lists.

**Do next:**

4. Make the approval reference **mandatory** in LedgerOne, checked against an approval register, with a second approver for bank changes.
5. Run the Provenance Guard as a gate before every payment run.
6. Review every integration yearly, as the policy already requires (E10), and close the open audit findings (E11).
7. Route outside security notices to IT security, not the accounts mailbox. Ask Legal to confirm breach-notification duties to customers and regulators.
8. Keep API logs for at least a year, and synchronise BlueVault's clock.

**Open questions that the evidence package would settle:** whether money left on 8 September (the payment file), who owns the attacker IPs (E20), and exactly which records were exported (E02).
