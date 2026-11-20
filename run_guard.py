"""
Command-line runner for the Payment-Run Provenance Guard.

    python run_guard.py <evidence_folder> [--out output] [--hold 60] [--review 30] [--window 3]

Reads E19 (required) plus E01/E18, E04, E15, E17 if present, writes decisions.csv and report.md.
If the folder holds labels_*.csv (TEST data only), it also prints accuracy.
"""
import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from engine.guard import Settings, evaluate, load_folder, metrics  # noqa: E402
from engine.report import build_report  # noqa: E402


def main():
    ap = argparse.ArgumentParser(description="Payment-Run Provenance Guard")
    ap.add_argument("folder")
    ap.add_argument("--out", default="output")
    ap.add_argument("--hold", type=int, default=60)
    ap.add_argument("--review", type=int, default=30)
    ap.add_argument("--window", type=int, default=3, help="risk window in days before a payment run")
    a = ap.parse_args()

    s = Settings(hold_threshold=a.hold, review_threshold=a.review, risk_window_days=a.window)
    data = load_folder(a.folder)
    print("Loaded:", ", ".join(f"{k} ({len(v)} rows)" for k, v in sorted(data.items())))
    decisions, clocks = evaluate(data, s)
    m = metrics(decisions, data.get("LABELS"))

    out = Path(a.out)
    out.mkdir(parents=True, exist_ok=True)
    decisions.drop(columns=["chain"]).to_csv(out / "decisions.csv", index=False)
    (out / "report.md").write_text(build_report(decisions, clocks, m, s))

    bank = decisions[decisions["is_bank"]]
    print(f"\nBank-detail changes: {len(bank)}  ->  "
          + ", ".join(f"{k}: {v}" for k, v in bank["decision"].value_counts().items()))
    print("\nHELD changes:")
    for _, r in bank[bank["decision"] == "HOLD"].iterrows():
        print(f"  {r.change_id}  {r.ts_ist} IST  {r.vendor_name:<32} {r.field:<13} score {r.score}")
    if m:
        print(f"\nTEST accuracy: {m['fraud_held']}/{m['frauds']} attacks held "
              f"({m['detection_rate']}%), {m['fraud_review']} sent to review, {m['fraud_missed']} missed; "
              f"false alarms (normal changes held): {m['benign_held']}/{m['benign']}")
    print(f"\nWrote {out/'decisions.csv'} and {out/'report.md'}")


if __name__ == "__main__":
    main()
