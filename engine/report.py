"""Markdown report for the proof pack."""
from datetime import datetime, timezone

from .guard import RULES


def build_report(decisions, clocks, m, s):
    bank = decisions[decisions["is_bank"]]
    counts = bank["decision"].value_counts().to_dict()
    lines = [
        "# Payment-Run Provenance Guard — run report",
        f"Generated {datetime.now(timezone.utc):%Y-%m-%d %H:%M} UTC",
        "",
        "## Settings",
        f"- HOLD at score >= {s.hold_threshold}, REVIEW at >= {s.review_threshold}",
        f"- Risk window: {s.risk_window_days} days before a payment run (runs on day {s.payment_days} of each month, India time)",
        f"- Expected integration networks: {', '.join(s.expected_networks)}; office: {', '.join(s.internal_networks)}",
        "",
        "## Clocks (all converted to UTC)",
        "| File | Column | Basis | Minutes added | Rows |",
        "| --- | --- | --- | --- | --- |",
    ]
    for _, c in clocks.iterrows():
        lines.append(f"| {c['file']} | {c['column']} | {c['basis']} | {c['minutes_added']} | {c['rows']} |")
    lines += [
        "",
        "## Decisions on bank-detail changes",
        f"{len(bank)} bank-detail changes: " + ", ".join(f"{k} {v}" for k, v in counts.items()),
        "",
        "| Change | Time (IST) | Vendor | Field | Decision | Score | Reasons |",
        "| --- | --- | --- | --- | --- | --- | --- |",
    ]
    for _, r in bank[bank["decision"] != "ALLOW"].sort_values("score", ascending=False).iterrows():
        lines.append(f"| {r.change_id} | {r.ts_ist} | {r.vendor_name} | {r.field} | {r.decision} | {r.score} | "
                     f"{r.reasons} |")
    if m:
        lines += [
            "",
            "## Accuracy on TEST data (labels are synthetic, not case findings)",
            f"- Attacks held: {m['fraud_held']}/{m['frauds']} ({m['detection_rate']}%)",
            f"- Attacks sent to review: {m['fraud_review']}; missed: {m['fraud_missed']}",
            f"- Normal bank changes held (false alarms): {m['benign_held']}/{m['benign']} ({m['false_alarm_rate']}%)",
            f"- Normal bank changes sent to review: {m['benign_review']}",
            "",
            "| Change | Scenario | Label | Decision | Score |",
            "| --- | --- | --- | --- | --- |",
        ]
        t = m["table"]
        for _, r in t[(t["label"] == "fraud") | (t["decision"] != "ALLOW")].iterrows():
            lines.append(f"| {r.change_id} | {r.scenario} | {r.label} | {r.decision} | {r.score} |")
    lines += ["", "## Rule weights", "| Rule | Points | On |", "| --- | --- | --- |"]
    for k, (desc, _) in RULES.items():
        lines.append(f"| {desc} | {s.weights.get(k)} | {'yes' if s.enabled.get(k, True) else 'no'} |")
    lines += ["", "## Known limits",
              "- A change with a valid-looking approval reference, from the expected network, by a key with a "
              "history of approved bank changes, scores low. Approval references are not verified against an "
              "approval register (none was supplied).",
              "- Results depend on log completeness: LedgerOne keeps API logs for 90 days; BlueVault's clock is "
              "unsynchronised; E15 host labels and E17 indicators come from the outside company and are unverified."]
    return "\n".join(lines) + "\n"
